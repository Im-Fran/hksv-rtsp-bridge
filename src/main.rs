#[allow(dead_code)]
mod camera;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod hap;
#[allow(dead_code)]
mod hds;
#[allow(dead_code)]
mod media;
#[allow(dead_code)]
mod motion;
#[allow(dead_code)]
mod redact;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use std::sync::{Mutex, RwLock};
use tokio::sync::watch;

use config::Legacy;
use hap::crypto::Pairings;
use hap::mdns::{Advertiser, needs_update};
use hap::server::{Notifier, serve};
use hap::store::FileStore;
use media::ingest::Stream;
use media::snapshot::Snapshotter;

const USAGE: &str = "usage: hksv-rtsp-bridge [--config <path>]  (default /etc/hksv-rtsp-bridge/config.toml)";

/// lowercase ASCII, spaces/underscores -> '-', no accents or other symbols.
fn slug(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9') => Some(c),
            ' ' | '_' | '-' => Some('-'),
            _ => match c {
                'á' | 'à' | 'ä' | 'â' | 'Á' | 'À' | 'Ä' | 'Â' => Some('a'),
                'é' | 'è' | 'ë' | 'ê' | 'É' | 'È' | 'Ë' | 'Ê' => Some('e'),
                'í' | 'ì' | 'ï' | 'î' | 'Í' | 'Ì' | 'Ï' | 'Î' => Some('i'),
                'ó' | 'ò' | 'ö' | 'ô' | 'Ó' | 'Ò' | 'Ö' | 'Ô' => Some('o'),
                'ú' | 'ù' | 'ü' | 'û' | 'Ú' | 'Ù' | 'Ü' | 'Û' => Some('u'),
                'ñ' | 'Ñ' => Some('n'),
                _ => None,
            },
        })
        .collect()
}

fn parse_args() -> Result<Option<PathBuf>> {
    let mut path = PathBuf::from("/etc/hksv-rtsp-bridge/config.toml");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "--config" => path = args.next().context("--config requires a path")?.into(),
            other => bail!("unknown argument: {other}\n{USAGE}"),
        }
    }
    Ok(Some(path))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let Some(path) = parse_args()? else {
        return Ok(());
    };
    let cfg = config::load(&path)?;

    let mut seen = HashSet::new();
    for cam in &cfg.camera {
        let key = slug(&cam.name);
        if key.is_empty() || !seen.insert(key.clone()) {
            bail!(
                "camera name {:?} produces an empty or duplicate identifier ({key:?})",
                cam.name
            );
        }
    }

    // One ingest (main+sub) per camera; waiting for their info runs in parallel so it doesn't add 15 s
    // per camera.
    let mut started: std::collections::VecDeque<_> = cfg
        .camera
        .iter()
        .map(|cam| {
            let main = Stream::spawn(cam.main.clone(), cfg.server.prebuffer_secs);
            let sub = Stream::spawn(cam.sub.clone(), cfg.server.prebuffer_secs);
            let name = cam.name.clone();
            tokio::spawn(async move {
                let (mi, si) = camera::wait_infos(&name, &main, &sub).await;
                (main, sub, mi, si)
            })
        })
        .collect();

    // The advertisers are kept alive until the end of main.
    let mut advertisers = Vec::new();
    let mut servers = tokio::task::JoinSet::new();
    for (i, cam) in cfg.camera.iter().enumerate() {
        let port = cfg.server.base_port + i as u16;
        let key = slug(&cam.name);
        let store = FileStore::open(&cfg.server.state_dir, &key)?;
        let device_id = store.identity().device_id.clone();

        let (main_stream, sub_stream, main_info, sub_info) =
            started.pop_front().expect("one per camera").await?;
        let tiers = camera::tiers_for(&main_info, &sub_info);
        let hsv3 = cfg.server.hsv3;
        let acc = Arc::new(RwLock::new(if hsv3 {
            camera::build_accessory(
                cam,
                &device_id,
                &tiers,
                camera::sensor_uuid(&device_id),
                cfg.server.legacy == Legacy::Same,
                cfg.server.max_resolution,
            )
        } else {
            // A single accessory with the classic services (same identity as before).
            camera::build_classic_accessory(&cam.name, &device_id, cfg.server.max_resolution)
        }));
        let notifier = Notifier::new();
        // Without motion configured, the receiver stays false (the emitter is released).
        let mut motion_rx = watch::channel(false).1;
        if let Some(url) = &cam.motion {
            match motion::spawn(
                url,
                std::time::Duration::from_secs(cfg.server.motion_hold_secs.into()),
            ) {
                Ok(rx) => {
                    motion::hook(rx.clone(), acc.clone(), notifier.clone());
                    motion_rx = rx;
                }
                Err(e) => tracing::warn!("{}: motion disabled: {e}", cam.name),
            }
        }
        // Remote view: the sub stream (Low tier, passthrough) saves bandwidth on mobile.
        let remote_tier = tiers
            .iter()
            .find(|t| t.source == camera::tiers::TierSource::SubCopy)
            .or(tiers.last())
            .cloned()
            .expect("tiers_for returns at least one tier");
        let snapshotter = Arc::new(Snapshotter::new(sub_stream.clone(), cam.snapshot.clone()));
        let webrtc = camera::WebRtc::new(
            main_stream.clone(),
            sub_stream.clone(),
            remote_tier,
            camera::count_hook(acc.clone(), notifier.clone()),
        );
        let new_sessions = || {
            Arc::new(camera::Sessions::new(
                main_stream.clone(),
                sub_stream.clone(),
                tiers.clone(),
                cfg.server.hwaccel,
            ))
        };
        let handler = Arc::new(camera::CameraHandler {
            accessory: acc.clone(),
            snapshotter: snapshotter.clone(),
            webrtc: webrtc.clone(),
            sessions: new_sessions(),
            hds: hds::HdsServer::new(),
        });
        if !hsv3 {
            camera::recording::Recorder::new(main_stream.clone(), motion_rx.clone(), acc.clone())
                .start(&handler.hds);
        }
        host(
            &cfg.server,
            &cam.name,
            port,
            store,
            (acc, handler, notifier),
            &redact::redact(&cam.main),
            &mut advertisers,
            &mut servers,
        )
        .await?;

        if hsv3 && cfg.server.legacy == Legacy::Separate {
            // Own identity (different device_id): the Home app sees it as a separate camera.
            let lname = camera::legacy::separate_name(&cam.name);
            let lstore =
                FileStore::open(&cfg.server.state_dir, &camera::legacy::separate_key(&key))?;
            let lacc = Arc::new(RwLock::new(camera::build_classic_accessory(
                &lname,
                &lstore.identity().device_id,
                cfg.server.max_resolution,
            )));
            let lnotifier = Notifier::new();
            motion::hook(motion_rx.clone(), lacc.clone(), lnotifier.clone());
            let handler = Arc::new(camera::CameraHandler {
                accessory: lacc.clone(),
                snapshotter,
                webrtc,
                sessions: new_sessions(),
                hds: hds::HdsServer::new(),
            });
            camera::recording::Recorder::new(main_stream.clone(), motion_rx.clone(), lacc.clone())
                .start(&handler.hds);
            host(
                &cfg.server,
                &lname,
                port + config::LEGACY_PORT_OFFSET,
                lstore,
                (lacc, handler, lnotifier),
                "(H.264 from main/sub)",
                &mut advertisers,
                &mut servers,
            )
            .await?;
        }
    }

    let result = tokio::select! {
        r = servers.join_next() => r.expect("at least one camera").map_err(Into::into).and_then(|r| r),
        _ = shutdown_signal() => { tracing::info!("exiting"); Ok(()) }
    };
    // mDNS goodbye (the Advertisers share an Arc with tasks, so dropping them is not enough).
    for a in &advertisers {
        a.stop();
    }
    // Grace period so mdns-sd flushes its packets before exiting.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    result
}

type Hosted = (
    Arc<RwLock<hap::model::Accessory>>,
    Arc<camera::CameraHandler>,
    Notifier,
);

/// Publishes an accessory: TCP port, mDNS announcement and HAP server.
#[allow(clippy::too_many_arguments)]
async fn host(
    server: &config::Server,
    name: &str,
    port: u16,
    mut store: FileStore,
    (acc, handler, notifier): Hosted,
    source: &str,
    advertisers: &mut Vec<Arc<Advertiser>>,
    servers: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<()> {
    let device_id = store.identity().device_id.clone();
    let config_number = store.bump_config_number()?;
    let is_paired = !store.is_empty();
    let listener = tokio::net::TcpListener::bind((server.bind, port))
        .await
        .with_context(|| format!("listening on {}:{port}", server.bind))?;
    let (paired_tx, mut paired_rx) = watch::channel(is_paired);
    let advertiser = Arc::new(Advertiser::start(
        name,
        &device_id,
        port,
        config_number,
        camera::CAMERA_CATEGORY,
        is_paired,
    )?);
    tracing::info!(
        "camera {name:?} ({device_id}) listening on {}:{port}, c#={config_number}, paired={is_paired}, main={source}",
        server.bind,
    );

    let adv = advertiser.clone();
    let name = name.to_string();
    tokio::spawn(async move {
        let mut last = is_paired;
        while paired_rx.changed().await.is_ok() {
            let p = *paired_rx.borrow();
            if !needs_update(&mut last, p) {
                continue;
            }
            tracing::info!("{name}: paired={p}");
            if let Err(e) = adv.update(config_number, p) {
                tracing::warn!("{name}: could not update mDNS: {e}");
            }
        }
    });
    advertisers.push(advertiser);

    let (code, store) = (server.setup_code.clone(), Arc::new(Mutex::new(store)));
    servers.spawn(serve(
        listener, acc, handler, store, code, notifier, paired_tx,
    ));
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::slug;

    #[test]
    fn slug_cases() {
        assert_eq!(slug("Balcón"), "balcon");
        assert_eq!(slug("Kitchen 2"), "kitchen-2");
        assert_eq!(slug("Back_Yard!"), "back-yard");
        assert_eq!(slug("Niño"), "nino");
    }
}
