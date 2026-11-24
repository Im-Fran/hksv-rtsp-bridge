//! HAP HTTP server: pairing in plaintext and, after pair-verify, HTTP encrypted per frame.
//!
//! One task per connection (`handle_conn`). Shared state lives in `Server`; events
//! (`Notifier`) and forced session closure travel over a per-connection channel.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use super::crypto::{AccessoryIdentity, FrameCipher, Pairings, SessionKeys};
use super::http::{self, Request, Response};
use super::model::{Accessory, Characteristic, Handler, Perms, ResourceRequest};
use super::pair_setup::PairSetup;
use super::pair_verify::PairVerify;
use super::store::FileStore;
use super::tlv8::{
    ERR_AUTHENTICATION, ERR_BUSY, ERR_MAX_TRIES, ERR_UNKNOWN, T_ERROR, T_IDENTIFIER, T_METHOD,
    T_PERMISSIONS, T_PUBLIC_KEY, T_STATE, Tlv8,
};
use super::uuids;

/// Per-connection event queue; if it overflows (slow client) the connection is closed.
const EVENT_QUEUE: usize = 256;
/// Failed pair-setup attempts before responding with MaxTries.
const MAX_SETUP_ATTEMPTS: u32 = 100;

const ST_UNAUTHORIZED: i64 = -70401;
const ST_COMMUNICATION: i64 = -70402;
const ST_READ_ONLY: i64 = -70404;
const ST_WRITE_ONLY: i64 = -70405;
const ST_NO_NOTIFY: i64 = -70406;
const ST_NOT_FOUND: i64 = -70409;
const ST_INVALID: i64 = -70410;

enum Out {
    Event(Vec<u8>),
    Close,
}

struct Conn {
    controller: Option<String>,
    subs: HashSet<u64>,
    tx: mpsc::Sender<Out>,
}

/// Sends `EVENT/1.0` events to subscribed verified connections. Cloneable.
#[derive(Clone, Default)]
pub struct Notifier(Arc<Mutex<HashMap<u64, Conn>>>);

impl Notifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Change originating in the accessory: sent to all subscribers of `iid`.
    pub fn notify(&self, iid: u64, v: Value) {
        let body = json!({"characteristics": [{"aid": 1, "iid": iid, "value": v}]});
        let ev = http::format_event(body.to_string().as_bytes());
        self.send_where(
            |c| c.controller.is_some() && c.subs.contains(&iid),
            || Out::Event(ev.clone()),
        );
    }

    /// Sends to connections matching `pred`; those with a full queue are dropped
    /// (dropping their `tx` closes the connection after draining what is already queued).
    fn send_where(&self, pred: impl Fn(&Conn) -> bool, msg: impl Fn() -> Out) {
        self.0.lock().unwrap().retain(|_, c| {
            !pred(c)
                || !matches!(
                    c.tx.try_send(msg()),
                    Err(mpsc::error::TrySendError::Full(_))
                )
        });
    }

    fn with(&self, id: u64, f: impl FnOnce(&mut Conn)) {
        if let Some(c) = self.0.lock().unwrap().get_mut(&id) {
            f(c);
        }
    }

    fn close_controller(&self, ctl: &str) {
        self.send_where(|c| c.controller.as_deref() == Some(ctl), || Out::Close);
    }
}

pub struct Server {
    accessory: Arc<RwLock<Accessory>>,
    handler: Arc<dyn Handler>,
    pub(crate) store: Arc<Mutex<FileStore>>,
    setup_code: String,
    hub: Notifier,
    paired: watch::Sender<bool>,
    /// A single pair-setup in progress per accessory: (owning connection, state machine).
    setup: Mutex<Option<(u64, PairSetup)>>,
    next_id: AtomicU64,
}

/// Addresses (peer, local) of the TCP connection serving the current task.
#[derive(Clone, Copy, Debug)]
pub struct ConnAddrs {
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

tokio::task_local! {
    static CONN_ADDRS: ConnAddrs;
    static SESSION_SECRET: [u8; 32];
}

/// Pair-verify shared secret of the HAP connection serving the current task
/// (`None` if not yet verified or outside a connection). Used to derive HDS keys.
pub fn current_shared_secret() -> Option<[u8; 32]> {
    SESSION_SECRET.try_with(|s| *s).ok()
}

/// Addresses of the current HAP connection (`None` outside a real connection, e.g. in tests).
pub fn current_conn() -> Option<ConnAddrs> {
    CONN_ADDRS.try_with(|a| *a).ok()
}

/// Serves HAP on `listener` until `accept` fails.
///
/// `notifier` is created beforehand with `Notifier::new()` and shared with whoever originates events.
/// `paired` reflects "at least one pairing exists" (updated after pair-setup and after removing
/// pairings); the caller sets the initial value and watches it with `subscribe()` for the mDNS `sf` flag.
pub async fn serve(
    listener: TcpListener,
    accessory: Arc<RwLock<Accessory>>,
    handler: Arc<dyn Handler>,
    store: Arc<Mutex<FileStore>>,
    setup_code: String,
    notifier: Notifier,
    paired: watch::Sender<bool>,
) -> Result<()> {
    let srv = Server::new(accessory, handler, store, setup_code, notifier, paired);
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let local = sock.local_addr().ok();
        let fut = handle_conn(srv.clone(), sock);
        match local {
            Some(local) => tokio::spawn(CONN_ADDRS.scope(
                ConnAddrs {
                    peer: SocketAddr::new(peer.ip().to_canonical(), peer.port()),
                    local: SocketAddr::new(local.ip().to_canonical(), local.port()),
                },
                fut,
            )),
            None => tokio::spawn(fut),
        };
    }
}

struct ConnState {
    verify: PairVerify,
    cipher: Option<FrameCipher>,
    controller: Option<String>,
    shared_secret: Option<[u8; 32]>,
    /// Prepared timed write: (pid, expiry).
    prepared: Option<(u64, Instant)>,
}

struct Reply {
    resp: Response,
    /// After sending this response in plaintext, encrypt with these keys.
    upgrade: Option<(SessionKeys, String)>,
    close: bool,
}

impl From<Response> for Reply {
    fn from(resp: Response) -> Self {
        Reply {
            resp,
            upgrade: None,
            close: false,
        }
    }
}

fn tlv_error(state: u8, code: u8) -> Response {
    Response::tlv(
        Tlv8::new()
            .push_u8(T_STATE, state)
            .push_u8(T_ERROR, code)
            .encode(),
    )
}

fn status_only(status: i64) -> Response {
    Response::json(
        if status == 0 { 200 } else { 400 },
        &json!({"status": status}),
    )
}

pub(crate) async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(srv: Arc<Server>, io: S) {
    let id = srv.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
    srv.hub.0.lock().unwrap().insert(
        id,
        Conn {
            controller: None,
            subs: HashSet::new(),
            tx,
        },
    );
    if let Err(e) = conn_loop(&srv, id, io, &mut rx).await {
        tracing::warn!(peer = id, error = %e, "HAP connection closed with error");
    }
    srv.hub.0.lock().unwrap().remove(&id);
    let mut slot = srv.setup.lock().unwrap();
    if slot.as_ref().is_some_and(|(o, _)| *o == id) {
        *slot = None;
    }
}

async fn conn_loop<S: AsyncRead + AsyncWrite + Unpin>(
    srv: &Server,
    id: u64,
    io: S,
    rx: &mut mpsc::Receiver<Out>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(io);
    let mut st = ConnState {
        verify: PairVerify::new(),
        cipher: None,
        controller: None,
        shared_secret: None,
        prepared: None,
    };
    let (mut raw, mut plain) = (BytesMut::new(), BytesMut::new());
    let mut chunk = vec![0u8; 4096];
    loop {
        tokio::select! {
            n = rd.read(&mut chunk) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                raw.extend_from_slice(&chunk[..n]);
                loop {
                    match &mut st.cipher {
                        Some(c) => {
                            while let Some(p) = c.decrypt(&mut raw)? {
                                plain.extend_from_slice(&p);
                            }
                        }
                        None => plain.extend_from_slice(&raw.split()),
                    }
                    let Some(req) = http::parse(&mut plain)? else { break };
                    let (method, path) = (req.method.clone(), req.path().to_owned());
                    let secret = st.shared_secret;
                    let fut = srv.route(id, &mut st, req);
                    let reply = match secret {
                        Some(s) => SESSION_SECRET.scope(s, fut).await,
                        None => fut.await,
                    };
                    tracing::debug!(peer = id, method = %method, path = %path, status = reply.resp.status, "hap request");
                    let bytes = reply.resp.format();
                    wr.write_all(&seal(&mut st.cipher, &bytes)).await?;
                    if let Some((keys, ctl)) = reply.upgrade {
                        let short: String = ctl.chars().take(8).collect();
                        tracing::info!(peer = id, controller = %short, "pair-verify completed");
                        st.cipher = Some(FrameCipher::new(keys.read, keys.write));
                        st.shared_secret = Some(keys.shared_secret);
                        srv.hub.with(id, |c| c.controller = Some(ctl.clone()));
                        st.controller = Some(ctl);
                    }
                    if reply.close {
                        return Ok(());
                    }
                }
            }
            out = rx.recv() => match out {
                Some(Out::Event(ev)) => wr.write_all(&seal(&mut st.cipher, &ev)).await?,
                Some(Out::Close) | None => return Ok(()),
            },
        }
    }
}

fn seal(cipher: &mut Option<FrameCipher>, bytes: &[u8]) -> Vec<u8> {
    match cipher {
        Some(c) => c.encrypt_frames(bytes),
        None => bytes.to_vec(),
    }
}

fn parse_ids(q: &str) -> Vec<(u64, u64)> {
    let ids = q
        .split('&')
        .find_map(|p| p.strip_prefix("id="))
        .unwrap_or("");
    ids.split(',')
        .filter_map(|s| {
            let (a, i) = s.split_once('.')?;
            Some((a.parse().ok()?, i.parse().ok()?))
        })
        .collect()
}

fn flag(q: &str, name: &str) -> bool {
    q.split('&')
        .any(|p| p.strip_prefix(name).and_then(|r| r.strip_prefix('=')) == Some("1"))
}

impl Server {
    pub(crate) fn new(
        accessory: Arc<RwLock<Accessory>>,
        handler: Arc<dyn Handler>,
        store: Arc<Mutex<FileStore>>,
        setup_code: String,
        hub: Notifier,
        paired: watch::Sender<bool>,
    ) -> Arc<Server> {
        Arc::new(Server {
            accessory,
            handler,
            store,
            setup_code,
            hub,
            paired,
            setup: Mutex::new(None),
            next_id: AtomicU64::new(1),
        })
    }

    #[cfg(test)]
    pub(crate) fn device_id(&self) -> String {
        self.store.lock().unwrap().identity().device_id.clone()
    }

    async fn route(&self, id: u64, st: &mut ConnState, req: Request) -> Reply {
        if st.cipher.is_none() {
            return match (req.method.as_str(), req.path()) {
                ("POST", "/pair-setup") => self.pair_setup(id, &req.body).into(),
                ("POST", "/pair-verify") => self.pair_verify(st, &req.body),
                _ => status_only_code(470, ST_UNAUTHORIZED).into(),
            };
        }
        match (req.method.as_str(), req.path()) {
            ("GET", "/accessories") => {
                Response::json(200, &self.accessory.read().unwrap().to_json())
            }
            ("GET", "/characteristics") => self.get_chars(id, req.query()).await,
            ("PUT", "/characteristics") => self.put_chars(id, st, &req.body).await,
            ("PUT", "/prepare") => prepare(st, &req.body),
            ("POST", "/pairings") => return self.pairings(st, &req.body),
            ("POST", "/resource") => self.resource(&req.body).await,
            _ => Response::empty(404),
        }
        .into()
    }

    fn identity_copy(store: &FileStore) -> AccessoryIdentity {
        let i = store.identity();
        AccessoryIdentity {
            device_id: i.device_id.clone(),
            signing: SigningKey::from_bytes(&i.signing.to_bytes()),
        }
    }

    fn pair_setup(&self, id: u64, body: &[u8]) -> Response {
        let Ok(tlv) = Tlv8::parse(body) else {
            return Response::empty(400);
        };
        let state = tlv.get_u8(T_STATE).ok().flatten().unwrap_or(0);
        let mut slot = self.setup.lock().unwrap();
        if state == 1 {
            if self.store.lock().unwrap().failed_attempts() >= MAX_SETUP_ATTEMPTS {
                return tlv_error(2, ERR_MAX_TRIES);
            }
            if slot.as_ref().is_some_and(|(owner, _)| *owner != id) {
                return tlv_error(2, ERR_BUSY);
            }
            *slot = Some((id, PairSetup::new()));
        }
        let Some((_, ps)) = slot.as_mut().filter(|(o, _)| *o == id) else {
            return tlv_error(state.wrapping_add(1), ERR_UNKNOWN);
        };
        let mut store = self.store.lock().unwrap();
        let ident = Self::identity_copy(&store);
        match ps.handle(
            body,
            &ident,
            &self.setup_code,
            &mut *store as &mut dyn Pairings,
        ) {
            Ok(resp) => {
                let failed = Tlv8::parse(&resp).is_ok_and(|t| t.get(T_ERROR).is_some());
                if state == 5 || failed {
                    *slot = None;
                }
                let t = Tlv8::parse(&resp).ok();
                let get = |k| t.as_ref().and_then(|t| t.get_u8(k).ok().flatten());
                let attempts = store.failed_attempts();
                let next = if get(T_STATE) == Some(4) && get(T_ERROR) == Some(ERR_AUTHENTICATION) {
                    attempts.saturating_add(1)
                } else if state == 5 && !failed {
                    0
                } else {
                    attempts
                };
                if next != attempts && store.set_failed_attempts(next).is_err() {
                    tracing::warn!("could not persist the pair-setup attempt counter");
                }
                self.paired.send_replace(!store.is_empty());
                Response::tlv(resp)
            }
            Err(_) => {
                *slot = None;
                Response::empty(400)
            }
        }
    }

    fn pair_verify(&self, st: &mut ConnState, body: &[u8]) -> Reply {
        let store = self.store.lock().unwrap();
        match st.verify.handle(body, store.identity(), &*store) {
            Ok((resp, keys)) => Reply {
                upgrade: keys.zip(st.verify.controller_id().map(str::to_owned)),
                resp: Response::tlv(resp),
                close: false,
            },
            Err(_) => Response::empty(400).into(),
        }
    }

    async fn get_chars(&self, id: u64, q: &str) -> Response {
        let (meta, perms, ty, ev) = (
            flag(q, "meta"),
            flag(q, "perms"),
            flag(q, "type"),
            flag(q, "ev"),
        );
        let mut items = Vec::new();
        let mut any_err = false;
        for (aid, iid) in parse_ids(q) {
            let c = self.find(aid, iid);
            let mut o = json!({"aid": aid, "iid": iid});
            let status = match &c {
                None => ST_NOT_FOUND,
                Some(c) if !c.perms.contains(Perms::PR) => ST_WRITE_ONLY,
                Some(c) => match self.handler.read(iid).await {
                    Ok(v) => {
                        o["value"] = v;
                        if ty {
                            o["type"] = uuids::short(&c.ty).into();
                        }
                        if perms {
                            o["perms"] = c.to_json()["perms"].clone();
                        }
                        if meta {
                            o["format"] = c.format.name().into();
                        }
                        if ev {
                            o["ev"] = self.is_subscribed(id, iid).into();
                        }
                        0
                    }
                    Err(e) => {
                        tracing::warn!("read of iid {iid} failed: {e}");
                        ST_COMMUNICATION
                    }
                },
            };
            if status != 0 {
                any_err = true;
                o.as_object_mut().map(|m| m.remove("value"));
            }
            o["status"] = status.into();
            items.push(o);
        }
        if !any_err {
            for o in &mut items {
                o.as_object_mut().map(|m| m.remove("status"));
            }
        }
        Response::json(
            if any_err { 207 } else { 200 },
            &json!({"characteristics": items}),
        )
    }

    fn is_subscribed(&self, id: u64, iid: u64) -> bool {
        self.hub
            .0
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|c| c.subs.contains(&iid))
    }

    fn find(&self, aid: u64, iid: u64) -> Option<Characteristic> {
        let acc = self.accessory.read().unwrap();
        (aid == acc.aid).then(|| acc.find(iid).cloned()).flatten()
    }

    async fn put_chars(&self, id: u64, st: &mut ConnState, body: &[u8]) -> Response {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return Response::empty(400);
        };
        let Some(list) = req["characteristics"].as_array() else {
            return Response::empty(400);
        };
        let pid = req["pid"].as_u64();
        // The pid is consumed in any case; if it doesn't match or has expired, the whole write fails.
        let timed_ok = pid.is_some_and(|p| {
            st.prepared
                .take()
                .is_some_and(|(pp, deadline)| pp == p && Instant::now() <= deadline)
        });
        let is_admin = {
            let me = st.controller.as_deref().unwrap_or("");
            self.store
                .lock()
                .unwrap()
                .list()
                .iter()
                .any(|(id, _, a)| id == me && *a)
        };
        let mut want_207 = false;
        let mut out = Vec::new();
        for item in list {
            let (aid, iid) = (
                item["aid"].as_u64().unwrap_or(0),
                item["iid"].as_u64().unwrap_or(0),
            );
            let r = item["r"].as_bool().unwrap_or(false);
            want_207 |= r;
            let mut o = json!({"aid": aid, "iid": iid});
            let status = match self.find(aid, iid) {
                None => ST_NOT_FOUND,
                Some(_) if pid.is_some() && !timed_ok => ST_INVALID,
                Some(c) => {
                    self.write_one(id, &c, item, r, (timed_ok, is_admin), &mut o)
                        .await
                }
            };
            o["status"] = status.into();
            want_207 |= status != 0;
            out.push(o);
        }
        if want_207 {
            Response::json(207, &json!({"characteristics": out}))
        } else {
            Response::empty(204)
        }
    }

    async fn write_one(
        &self,
        id: u64,
        c: &Characteristic,
        item: &Value,
        r: bool,
        (timed_ok, is_admin): (bool, bool),
        o: &mut Value,
    ) -> i64 {
        if let Some(ev) = item.get("ev").and_then(Value::as_bool) {
            if !c.perms.contains(Perms::EV) {
                return ST_NO_NOTIFY;
            }
            self.hub.with(id, |conn| {
                if ev {
                    conn.subs.insert(c.iid);
                } else {
                    conn.subs.remove(&c.iid);
                }
            });
        }
        let Some(v) = item.get("value") else { return 0 };
        if !c.perms.contains(Perms::PW) {
            return ST_READ_ONLY;
        }
        if c.perms.contains(Perms::TW) && !timed_ok {
            return ST_INVALID;
        }
        // Characteristics marked AdminOnly (Streaming/Motion Enabled) require an admin pairing.
        if c.perms.contains(Perms::AA) && !is_admin {
            return ST_UNAUTHORIZED;
        }
        // iOS sometimes sends 0/1 for bool.
        let v = match (c.format, v) {
            (super::model::Format::Bool, Value::Number(n)) => match n.as_u64() {
                Some(b @ (0 | 1)) => Value::Bool(b == 1),
                _ => return ST_INVALID,
            },
            _ => v.clone(),
        };
        match self.handler.write(c.iid, v, r).await {
            Ok(resp) => {
                if let Some(rv) = resp.filter(|_| r) {
                    o["value"] = rv;
                }
                0
            }
            Err(e) => {
                tracing::warn!("write of iid {} failed: {e}", c.iid);
                ST_COMMUNICATION
            }
        }
    }

    fn pairings(&self, st: &ConnState, body: &[u8]) -> Reply {
        let tlv = match Tlv8::parse(body) {
            Ok(t) => t,
            Err(_) => return Response::empty(400).into(),
        };
        let mut store = self.store.lock().unwrap();
        let me = st.controller.as_deref().unwrap_or("");
        if !store.list().iter().any(|(id, _, admin)| id == me && *admin) {
            return tlv_error(2, ERR_AUTHENTICATION).into();
        }
        let ok = || Tlv8::new().push_u8(T_STATE, 2);
        let mut close = false;
        let resp = match tlv.get_u8(T_METHOD).ok().flatten() {
            Some(3) => {
                let id = tlv
                    .get(T_IDENTIFIER)
                    .and_then(|b| std::str::from_utf8(b).ok());
                let key = tlv
                    .get(T_PUBLIC_KEY)
                    .and_then(|k| <[u8; 32]>::try_from(k).ok())
                    .and_then(|k| VerifyingKey::from_bytes(&k).ok());
                let admin = tlv.get_u8(T_PERMISSIONS).ok().flatten() == Some(1);
                match (id, key) {
                    (Some(id), Some(key)) => {
                        let clash = store.get(id).is_some_and(|k| k != key);
                        if clash || store.add(id.to_owned(), key, admin).is_err() {
                            tlv_error(2, ERR_UNKNOWN).body
                        } else {
                            ok().encode()
                        }
                    }
                    _ => tlv_error(2, ERR_UNKNOWN).body,
                }
            }
            Some(4) => {
                let Some(id) = tlv
                    .get(T_IDENTIFIER)
                    .and_then(|b| std::str::from_utf8(b).ok())
                else {
                    return tlv_error(2, ERR_UNKNOWN).into();
                };
                if store.remove(id).is_err() {
                    return tlv_error(2, ERR_UNKNOWN).into();
                }
                let mut removed = vec![id.to_owned()];
                // HAP: removing the last admin deletes all pairings.
                if !store.list().iter().any(|(_, _, admin)| *admin) {
                    removed.extend(store.list().into_iter().map(|(i, _, _)| i));
                    if store.clear_pairings().is_err() {
                        return tlv_error(2, ERR_UNKNOWN).into();
                    }
                }
                for r in &removed {
                    self.hub.close_controller(r);
                }
                close = removed.iter().any(|r| r == me);
                self.paired.send_replace(!store.is_empty());
                ok().encode()
            }
            Some(5) => {
                let mut t = ok();
                for (i, (id, key, admin)) in store.list().into_iter().enumerate() {
                    if i > 0 {
                        t = t.push_sep();
                    }
                    t = t
                        .push(T_IDENTIFIER, id.as_bytes())
                        .push(T_PUBLIC_KEY, &key.to_bytes())
                        .push_u8(T_PERMISSIONS, u8::from(admin));
                }
                t.encode()
            }
            _ => tlv_error(2, ERR_UNKNOWN).body,
        };
        Reply {
            resp: Response::tlv(resp),
            upgrade: None,
            close,
        }
    }

    /// POST /resource like go2rtc (`pkg/homekit/server.go`): 200, `Content-Type: image/jpeg`,
    /// JPEG body. Missing `image-width`/`image-height` = 0 = original size (go2rtc does not
    /// rescale in that case). Each request is logged at info.
    async fn resource(&self, body: &[u8]) -> Response {
        let t0 = std::time::Instant::now();
        let peer = current_conn().map_or("?".into(), |c| c.peer.to_string());
        tracing::info!(%peer, body = %String::from_utf8_lossy(body), "POST /resource");
        let Ok(v) = serde_json::from_slice::<Value>(body) else {
            tracing::warn!(%peer, "POST /resource with non-JSON body, 400");
            return Response::empty(400);
        };
        let dim = |k: &str| {
            v[k].as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0)
        };
        let (width, height) = (dim("image-width"), dim("image-height"));
        match self
            .handler
            .resource(ResourceRequest { width, height })
            .await
        {
            Ok(jpeg) => {
                tracing::info!(
                    %peer, width, height, bytes = jpeg.len(), ms = t0.elapsed().as_millis() as u64,
                    "POST /resource -> 200 image/jpeg"
                );
                Response::new(200, "image/jpeg", jpeg)
            }
            Err(e) => {
                tracing::warn!(%peer, "POST /resource failed: {e:#}");
                Response::json(500, &json!({"status": ST_COMMUNICATION}))
            }
        }
    }
}

fn status_only_code(code: u16, status: i64) -> Response {
    Response::json(code, &json!({"status": status}))
}

fn prepare(st: &mut ConnState, body: &[u8]) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Response::empty(400);
    };
    let (Some(ttl), Some(pid)) = (v["ttl"].as_u64(), v["pid"].as_u64()) else {
        return Response::empty(400);
    };
    st.prepared = Some((pid, Instant::now() + Duration::from_millis(ttl)));
    status_only(0)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    use anyhow::{Result, bail};
    use bytes::BytesMut;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::watch;

    use super::*;
    use crate::hap::crypto::FrameCipher;
    use crate::hap::http::{CT_JSON, CT_TLV8};
    use crate::hap::model::*;
    use crate::hap::store::FileStore;
    use crate::hap::test_controller::Controller;
    use crate::hap::tlv8::*;
    use crate::hap::uuids;

    const CODE: &str = "031-45-154";

    struct TestHandler;

    #[async_trait::async_trait]
    impl Handler for TestHandler {
        async fn read(&self, iid: u64) -> Result<Value> {
            if iid == 11 {
                bail!("boom")
            }
            Ok(json!(true))
        }
        async fn write(&self, _iid: u64, _v: Value, response: bool) -> Result<Option<Value>> {
            Ok(response.then(|| json!("resp")))
        }
        async fn resource(&self, r: ResourceRequest) -> Result<Vec<u8>> {
            Ok(format!("jpeg{}x{}", r.width, r.height).into_bytes())
        }
    }

    fn ch(iid: u64, ty: uuid::Uuid, format: Format, perms: Perms, value: Value) -> Characteristic {
        Characteristic {
            iid,
            ty,
            format,
            perms,
            value,
        }
    }

    fn test_accessory() -> Accessory {
        Accessory {
            aid: 1,
            services: vec![Service {
                iid: 1,
                ty: uuids::ACCESSORY_INFORMATION,
                primary: true,
                hidden: false,
                linked: Vec::new(),
                chars: vec![
                    ch(2, uuids::NAME, Format::String, Perms::PR, json!("Cam")),
                    ch(3, uuids::IDENTIFY, Format::Bool, Perms::PW, Value::Null),
                    ch(
                        10,
                        uuids::MOTION_DETECTED,
                        Format::Bool,
                        Perms::PR | Perms::PW | Perms::EV | Perms::WR,
                        json!(false),
                    ),
                    ch(
                        11,
                        uuids::MOTION_ENABLED,
                        Format::Bool,
                        Perms::PR,
                        json!(false),
                    ),
                    ch(
                        12,
                        uuids::ACTIVE,
                        Format::Bool,
                        Perms::PR | Perms::PW | Perms::TW,
                        json!(false),
                    ),
                ],
            }],
        }
    }

    struct Harness {
        srv: Arc<Server>,
        notifier: Notifier,
        paired: watch::Receiver<bool>,
        _dir: tempfile::TempDir,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open(dir.path(), "cam").unwrap();
        let (tx, paired) = watch::channel(false);
        let notifier = Notifier::new();
        let srv = Server::new(
            Arc::new(RwLock::new(test_accessory())),
            Arc::new(TestHandler),
            Arc::new(Mutex::new(store)),
            CODE.into(),
            notifier.clone(),
            tx,
        );
        Harness {
            srv,
            notifier,
            paired,
            _dir: dir,
        }
    }

    struct Client {
        io: DuplexStream,
        cipher: Option<FrameCipher>,
        raw: BytesMut,
        plain: BytesMut,
    }

    impl Client {
        fn connect(h: &Harness) -> Client {
            let (a, b) = tokio::io::duplex(64 * 1024);
            tokio::spawn(handle_conn(h.srv.clone(), b));
            Client {
                io: a,
                cipher: None,
                raw: BytesMut::new(),
                plain: BytesMut::new(),
            }
        }

        async fn send(&mut self, method: &str, path: &str, ct: &str, body: &[u8]) {
            let mut req = format!(
                "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            req.extend(body);
            let wire = match &mut self.cipher {
                Some(c) => c.encrypt_frames(&req),
                None => req,
            };
            self.io.write_all(&wire).await.unwrap();
        }

        /// Reads a complete HTTP/EVENT message: (start line, body). `None` if the server closed.
        async fn recv(&mut self) -> Option<(String, Vec<u8>)> {
            loop {
                if let Some(end) = self.plain.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8(self.plain[..end].to_vec()).unwrap();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    if self.plain.len() >= end + 4 + len {
                        let body = self.plain[end + 4..end + 4 + len].to_vec();
                        let _ = self.plain.split_to(end + 4 + len);
                        return Some((head.lines().next().unwrap().to_string(), body));
                    }
                }
                let mut chunk = [0u8; 4096];
                let n = tokio::time::timeout(Duration::from_secs(5), self.io.read(&mut chunk))
                    .await
                    .expect("timed out waiting for the server")
                    .unwrap_or(0);
                if n == 0 {
                    return None;
                }
                match &mut self.cipher {
                    Some(c) => {
                        self.raw.extend_from_slice(&chunk[..n]);
                        while let Some(p) = c.decrypt(&mut self.raw).unwrap() {
                            self.plain.extend_from_slice(&p);
                        }
                    }
                    None => self.plain.extend_from_slice(&chunk[..n]),
                }
            }
        }

        async fn request(
            &mut self,
            method: &str,
            path: &str,
            ct: &str,
            body: &[u8],
        ) -> (String, Vec<u8>) {
            self.send(method, path, ct, body).await;
            self.recv().await.expect("connection closed")
        }

        async fn json(&mut self, method: &str, path: &str, body: &Value) -> (String, Value) {
            let (line, b) = self
                .request(method, path, CT_JSON, body.to_string().as_bytes())
                .await;
            let v = if b.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&b).unwrap()
            };
            (line, v)
        }

        /// Runs a plaintext TLV8 request from a synchronous closure (for `*_via`).
        fn tlv_blocking(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
            let (line, resp) = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(self.request("POST", path, CT_TLV8, body))
            });
            assert!(line.starts_with("HTTP/1.1 200"), "{line}");
            Ok(resp)
        }

        async fn pair_setup(
            &mut self,
            ctl: &Controller,
            h: &Harness,
        ) -> ed25519_dalek::VerifyingKey {
            let id = h.srv.device_id();
            self.pair_setup_with(ctl, &id, CODE)
        }

        fn pair_setup_with(
            &mut self,
            ctl: &Controller,
            dev: &str,
            code: &str,
        ) -> ed25519_dalek::VerifyingKey {
            ctl.pair_setup_via(&mut |m| self.tlv_blocking("/pair-setup", m), dev, code)
                .unwrap()
        }

        /// Pair-setup expected to fail; returns true if it failed.
        fn pair_setup_with_err(&mut self, ctl: &Controller, dev: &str, code: &str) -> bool {
            ctl.pair_setup_via(&mut |m| self.tlv_blocking("/pair-setup", m), dev, code)
                .is_err()
        }

        fn verify(&mut self, ctl: &Controller, acc_ltpk: &ed25519_dalek::VerifyingKey) {
            let keys = ctl
                .pair_verify_via(&mut |m| self.tlv_blocking("/pair-verify", m), acc_ltpk)
                .unwrap();
            self.cipher = Some(FrameCipher::new(keys.write, keys.read));
        }
    }

    /// Paired and verified client.
    async fn paired_client(h: &Harness, ctl: &Controller) -> Client {
        let mut c = Client::connect(h);
        let ltpk = c.pair_setup(ctl, h).await;
        let mut c2 = Client::connect(h);
        c2.verify(ctl, &ltpk);
        drop(c);
        c2
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_accessories_requires_verify() {
        let h = harness();
        let mut c = Client::connect(&h);
        let (line, body) = c.request("GET", "/accessories", CT_JSON, b"").await;
        assert!(line.starts_with("HTTP/1.1 470"), "{line}");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"status": -70401})
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accessories_json_shape() {
        let h = harness();
        let ctl = Controller::new("ctl-1");
        let mut c = paired_client(&h, &ctl).await;
        let (line, v) = c.json("GET", "/accessories", &Value::Null).await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let acc = &v["accessories"][0];
        assert_eq!(acc["aid"], 1);
        assert_eq!(acc["services"][0]["type"], "3E");
        assert_eq!(acc["services"][0]["primary"], true);
        let chars = acc["services"][0]["characteristics"].as_array().unwrap();
        assert_eq!(
            chars[0],
            json!({"iid": 2, "type": "23", "perms": ["pr"], "format": "string", "value": "Cam"})
        );
        assert!(chars[1].get("value").is_none(), "write-only without value");
        assert_eq!(chars[2]["perms"], json!(["pr", "pw", "ev", "wr"]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_characteristics_write_response() {
        let h = harness();
        let ctl = Controller::new("ctl-1");
        let mut c = paired_client(&h, &ctl).await;
        let (line, v) = c
            .json(
                "PUT",
                "/characteristics",
                &json!({"characteristics": [{"aid": 1, "iid": 10, "value": true, "r": true}]}),
            )
            .await;
        assert!(line.starts_with("HTTP/1.1 207"), "{line}");
        assert_eq!(
            v,
            json!({"characteristics": [{"aid": 1, "iid": 10, "status": 0, "value": "resp"}]})
        );
        // no r: 204
        let (line, _) = c
            .json(
                "PUT",
                "/characteristics",
                &json!({"characteristics": [{"aid": 1, "iid": 10, "value": true}]}),
            )
            .await;
        assert!(line.starts_with("HTTP/1.1 204"), "{line}");
        // per-item errors
        let (line, v) = c
            .json("PUT", "/characteristics", &json!({"characteristics": [
                {"aid": 1, "iid": 2, "value": "x"}, {"aid": 1, "iid": 99, "value": 1}, {"aid": 1, "iid": 3, "value": true}]}))
            .await;
        assert!(line.starts_with("HTTP/1.1 207"), "{line}");
        let st: Vec<i64> = v["characteristics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["status"].as_i64().unwrap())
            .collect();
        assert_eq!(st, [-70404, -70409, 0]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_characteristics_and_resource() {
        let h = harness();
        let mut c = paired_client(&h, &Controller::new("ctl-1")).await;
        let (line, v) = c
            .json("GET", "/characteristics?id=1.2,1.10", &Value::Null)
            .await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        assert_eq!(
            v["characteristics"][1],
            json!({"aid": 1, "iid": 10, "value": true})
        );
        let (line, v) = c
            .json("GET", "/characteristics?id=1.2,1.11,1.3", &Value::Null)
            .await;
        assert!(line.starts_with("HTTP/1.1 207"), "{line}");
        let st: Vec<i64> = v["characteristics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["status"].as_i64().unwrap())
            .collect();
        assert_eq!(st, [0, -70402, -70405]);
        let (line, body) = c
            .request(
                "POST",
                "/resource",
                CT_JSON,
                br#"{"resource-type":"image","image-width":320,"image-height":240}"#,
            )
            .await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        assert_eq!(body, b"jpeg320x240");
        let (line, body) = c
            .request(
                "POST",
                "/resource",
                CT_JSON,
                br#"{"resource-type":"image"}"#,
            )
            .await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        assert_eq!(body, b"jpeg0x0");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timed_write_requires_prepare() {
        let h = harness();
        let mut c = paired_client(&h, &Controller::new("ctl-1")).await;
        let w = |pid: Option<u64>| {
            let mut b = json!({"characteristics": [{"aid": 1, "iid": 12, "value": true}]});
            if let Some(p) = pid {
                b["pid"] = p.into();
            }
            b
        };
        let (_, v) = c.json("PUT", "/characteristics", &w(None)).await;
        assert_eq!(v["characteristics"][0]["status"], -70410);
        let (line, v) = c
            .json("PUT", "/prepare", &json!({"ttl": 5000, "pid": 7}))
            .await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        assert_eq!(v, json!({"status": 0}));
        let (line, _) = c.json("PUT", "/characteristics", &w(Some(7))).await;
        assert!(line.starts_with("HTTP/1.1 204"), "{line}");
        // the pid is consumed
        let (_, v) = c.json("PUT", "/characteristics", &w(Some(7))).await;
        assert_eq!(v["characteristics"][0]["status"], -70410);
        // expired
        c.json("PUT", "/prepare", &json!({"ttl": 10, "pid": 8}))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (_, v) = c.json("PUT", "/characteristics", &w(Some(8))).await;
        assert_eq!(v["characteristics"][0]["status"], -70410);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_subscription() {
        let h = harness();
        let mut c = paired_client(&h, &Controller::new("ctl-1")).await;
        h.notifier.notify(10, json!(true)); // no subscription: nothing arrives
        let (line, _) = c
            .json(
                "PUT",
                "/characteristics",
                &json!({"characteristics": [{"aid": 1, "iid": 10, "ev": true}]}),
            )
            .await;
        assert!(line.starts_with("HTTP/1.1 204"), "{line}");
        h.notifier.notify(10, json!(true));
        let (line, body) = c.recv().await.unwrap();
        assert_eq!(line, "EVENT/1.0 200 OK");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"characteristics": [{"aid": 1, "iid": 10, "value": true}]})
        );
        // iid 2 does not support ev
        let (_, v) = c
            .json(
                "PUT",
                "/characteristics",
                &json!({"characteristics": [{"aid": 1, "iid": 2, "ev": true}]}),
            )
            .await;
        assert_eq!(v["characteristics"][0]["status"], -70406);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_pair_setup_gets_busy() {
        let h = harness();
        let mut a = Client::connect(&h);
        let mut b = Client::connect(&h);
        let m1 = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 0)
            .encode();
        let (line, r) = a.request("POST", "/pair-setup", CT_TLV8, &m1).await;
        assert!(line.starts_with("HTTP/1.1 200"));
        assert_eq!(Tlv8::parse(&r).unwrap().get_u8(T_STATE).unwrap(), Some(2));
        let (_, r) = b.request("POST", "/pair-setup", CT_TLV8, &m1).await;
        let t = Tlv8::parse(&r).unwrap();
        assert_eq!(
            (t.get_u8(T_STATE).unwrap(), t.get_u8(T_ERROR).unwrap()),
            (Some(2), Some(ERR_BUSY))
        );
        // once `a` closes, `b` can start
        drop(a);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (_, r) = b.request("POST", "/pair-setup", CT_TLV8, &m1).await;
        assert!(Tlv8::parse(&r).unwrap().get(T_PUBLIC_KEY).is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pair_setup_max_tries() {
        let h = harness();
        h.srv
            .store
            .lock()
            .unwrap()
            .set_failed_attempts(100)
            .unwrap();
        let mut c = Client::connect(&h);
        let m1 = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 0)
            .encode();
        let (_, r) = c.request("POST", "/pair-setup", CT_TLV8, &m1).await;
        let t = Tlv8::parse(&r).unwrap();
        assert_eq!(
            (t.get_u8(T_STATE).unwrap(), t.get_u8(T_ERROR).unwrap()),
            (Some(2), Some(ERR_MAX_TRIES))
        );
        assert!(h.srv.setup.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_code_increments_and_success_resets() {
        let h = harness();
        let ctl = Controller::new("ctl-1");
        let mut c = Client::connect(&h);
        let id = h.srv.device_id();
        assert!(c.pair_setup_with_err(&ctl, &id, "999-99-999"));
        assert_eq!(h.srv.store.lock().unwrap().failed_attempts(), 1);
        let mut c = Client::connect(&h);
        c.pair_setup(&ctl, &h).await;
        assert_eq!(h.srv.store.lock().unwrap().failed_attempts(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tampered_frame_closes_connection() {
        let h = harness();
        let mut c = paired_client(&h, &Controller::new("ctl-1")).await;
        let mut wire = c
            .cipher
            .as_mut()
            .unwrap()
            .encrypt_frames(b"GET /accessories HTTP/1.1\r\n\r\n");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        c.io.write_all(&wire).await.unwrap();
        assert!(c.recv().await.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removing_last_admin_removes_non_admin_pairings_too() {
        let h = harness();
        let ctl = Controller::new("ctl-1");
        let mut c1 = Client::connect(&h);
        let ltpk = c1.pair_setup(&ctl, &h).await;
        let mut admin = Client::connect(&h);
        admin.verify(&ctl, &ltpk);
        let guest = Controller::new("guest");
        let add = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 3)
            .push(T_IDENTIFIER, b"guest")
            .push(T_PUBLIC_KEY, &guest.signing.verifying_key().to_bytes())
            .push_u8(T_PERMISSIONS, 0)
            .encode();
        let (_, r) = admin.request("POST", "/pairings", CT_TLV8, &add).await;
        assert_eq!(Tlv8::parse(&r).unwrap().get_u8(T_STATE).unwrap(), Some(2));
        let mut g = Client::connect(&h);
        g.verify(&guest, &ltpk);
        let rm = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 4)
            .push(T_IDENTIFIER, b"ctl-1")
            .encode();
        admin.request("POST", "/pairings", CT_TLV8, &rm).await;
        assert!(g.recv().await.is_none(), "guest disconnected");
        assert!(h.srv.store.lock().unwrap().list().is_empty());
        assert!(!*h.paired.borrow());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bool_rejects_out_of_range_number() {
        let h = harness();
        let mut c = paired_client(&h, &Controller::new("ctl-1")).await;
        let (_, v) = c
            .json(
                "PUT",
                "/characteristics",
                &json!({"characteristics": [{"aid": 1, "iid": 10, "value": 5}]}),
            )
            .await;
        assert_eq!(v["characteristics"][0]["status"], -70410);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pairings_list_add_and_remove_last_admin_closes_sessions() {
        let mut h = harness();
        let ctl = Controller::new("ctl-1");
        let mut c1 = Client::connect(&h);
        let ltpk = c1.pair_setup(&ctl, &h).await;
        assert!(*h.paired.borrow_and_update());
        let mut c2 = Client::connect(&h);
        c2.verify(&ctl, &ltpk);
        let mut c3 = Client::connect(&h);
        c3.verify(&ctl, &ltpk);

        // list
        let body = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 5)
            .encode();
        let (line, r) = c2.request("POST", "/pairings", CT_TLV8, &body).await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let t = Tlv8::parse(&r).unwrap();
        assert_eq!(t.get(T_IDENTIFIER), Some(&b"ctl-1"[..]));
        assert_eq!(t.get_u8(T_PERMISSIONS).unwrap(), Some(1));

        // remove the last admin
        let body = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 4)
            .push(T_IDENTIFIER, b"ctl-1")
            .encode();
        let (_, r) = c2.request("POST", "/pairings", CT_TLV8, &body).await;
        assert_eq!(Tlv8::parse(&r).unwrap().get_u8(T_STATE).unwrap(), Some(2));
        assert!(c2.recv().await.is_none(), "c2 closed");
        assert!(c3.recv().await.is_none(), "c3 closed");
        assert!(h.paired.has_changed().unwrap());
        assert!(!*h.paired.borrow_and_update());
        assert!(h.srv.store.lock().unwrap().list().is_empty());
    }
}
