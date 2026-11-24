//! HomeKit Data Stream (HDS): encrypted TCP channel through which HomeKit Secure Video reads recordings.
//!
//! Flow: the controller writes Setup Data Stream Transport (131) with its `controllerKeySalt`;
//! [`HdsServer::prepare`] generates the `accessoryKeySalt`, derives the keys from the secret
//! shared in pair-verify, and replies with port + salt. The controller then opens a TCP connection to that
//! port; the first frame identifies which pending session it belongs to. Connections already
//! identified and with `control/hello` completed are yielded by [`HdsServer::connections`].

pub mod codec;
pub mod conn;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[allow(unused_imports)] // API for Task 19
pub use codec::DsValue;
#[allow(unused_imports)] // API for Task 19
pub use conn::{DataSendRequest, HdsConn, HdsKeys, Kind, Message, reason};

/// How long a prepared session waits for the controller to open the TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum number of prepared sessions that are not yet connected (anti-abuse).
const MAX_PENDING: usize = 8;
/// Ready connections not yet consumed before they are dropped (nobody called `connections()`).
const READY_QUEUE: usize = 4;

/// State of the response TLV for 131.
const ST_OK: u8 = 0;
const ST_ERROR: u8 = 1;
const ST_BUSY: u8 = 2;

/// Supported Data Stream Transport Configuration (130): one transport, TCP (0).
pub fn supported_config_tlv() -> Vec<u8> {
    use crate::hap::tlv8::Tlv8;
    Tlv8::new()
        .push(1, &Tlv8::new().push_u8(1, 0).encode())
        .encode()
}

struct Pending {
    id: u64,
    since: Instant,
    keys: HdsKeys,
}

#[derive(Default)]
struct State {
    next_id: u64,
    pending: Vec<Pending>,
}

pub struct HdsServer {
    state: Mutex<State>,
    /// One listener per local IP (same interface the controller's HAP connection arrived on).
    ports: tokio::sync::Mutex<HashMap<IpAddr, u16>>,
    ready_tx: mpsc::Sender<HdsConn<TcpStream>>,
    ready_rx: Mutex<Option<mpsc::Receiver<HdsConn<TcpStream>>>>,
}

impl HdsServer {
    pub fn new() -> Arc<Self> {
        let (ready_tx, rx) = mpsc::channel(READY_QUEUE);
        Arc::new(Self {
            state: Mutex::default(),
            ports: Default::default(),
            ready_tx,
            ready_rx: Mutex::new(Some(rx)),
        })
    }

    /// Identified HDS connections with hello completed. Can only be taken once.
    pub fn connections(&self) -> Option<mpsc::Receiver<HdsConn<TcpStream>>> {
        self.ready_rx.lock().unwrap().take()
    }

    /// Setup Data Stream Transport (131) over the ongoing HAP connection (secret and address
    /// local come from it). Returns the response TLV.
    pub async fn setup(self: &Arc<Self>, raw: &[u8]) -> Vec<u8> {
        let secret = crate::hap::server::current_shared_secret();
        let ip =
            crate::hap::server::current_conn().map_or(Ipv4Addr::LOCALHOST.into(), |c| c.local.ip());
        self.prepare(secret, ip, raw).await
    }

    pub async fn prepare(
        self: &Arc<Self>,
        secret: Option<[u8; 32]>,
        ip: IpAddr,
        raw: &[u8],
    ) -> Vec<u8> {
        use crate::hap::tlv8::Tlv8;
        let status = |s: u8| Tlv8::new().push_u8(1, s).encode();
        let Ok(t) = Tlv8::parse(raw) else {
            return status(ST_ERROR);
        };
        let salt = t.get(3).filter(|s| s.len() == 32);
        let (Some(secret), Some(salt), Ok(Some(0)), Ok(Some(0))) =
            (secret, salt, t.get_u8(1), t.get_u8(2))
        else {
            tracing::warn!("Setup Data Stream Transport invalid or without verified session");
            return status(ST_ERROR);
        };
        let acc_salt: [u8; 32] = rand::random();
        let keys = HdsKeys::derive(&secret, salt, &acc_salt);
        {
            let mut st = self.state.lock().unwrap();
            st.pending.retain(|p| p.since.elapsed() < CONNECT_TIMEOUT);
            if st.pending.len() >= MAX_PENDING {
                return status(ST_BUSY);
            }
            st.next_id += 1;
            let id = st.next_id;
            st.pending.push(Pending {
                id,
                since: Instant::now(),
                keys,
            });
        }
        let port = match self.port_for(ip).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("HDS: could not open listener on {ip}: {e:#}");
                return status(ST_ERROR);
            }
        };
        tracing::info!(%ip, port, "HDS: session prepared");
        Tlv8::new()
            .push_u8(1, ST_OK)
            .push(2, &Tlv8::new().push(1, &port.to_le_bytes()).encode())
            .push(3, &acc_salt)
            .encode()
    }

    async fn port_for(self: &Arc<Self>, ip: IpAddr) -> Result<u16> {
        let mut ports = self.ports.lock().await;
        if let Some(p) = ports.get(&ip) {
            return Ok(*p);
        }
        let l = TcpListener::bind(SocketAddr::new(ip, 0)).await?;
        let port = l.local_addr()?.port();
        ports.insert(ip, port);
        tokio::spawn(self.clone().listen(l));
        Ok(port)
    }

    async fn listen(self: Arc<Self>, l: TcpListener) {
        while let Ok((sock, peer)) = l.accept().await {
            let _ = sock.set_nodelay(true);
            let me = self.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(CONNECT_TIMEOUT, me.identify(sock)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(%peer, "HDS: connection dropped: {e:#}"),
                    Err(_) => tracing::warn!(%peer, "HDS: no hello in time"),
                }
            });
        }
    }

    async fn identify(&self, sock: TcpStream) -> Result<()> {
        let cands: Vec<(u64, HdsKeys)> = {
            let mut st = self.state.lock().unwrap();
            st.pending.retain(|p| p.since.elapsed() < CONNECT_TIMEOUT);
            st.pending.iter().map(|p| (p.id, p.keys.clone())).collect()
        };
        let keys: Vec<HdsKeys> = cands.iter().map(|(_, k)| k.clone()).collect();
        let (idx, conn) = HdsConn::accept(sock, &keys).await?;
        // A pending session serves only one connection.
        self.state
            .lock()
            .unwrap()
            .pending
            .retain(|p| p.id != cands[idx].0);
        tracing::info!("HDS: connection identified and hello completed");
        self.ready_tx
            .try_send(conn)
            .map_err(|_| anyhow::anyhow!("nobody consumes HDS connections; dropped"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap::tlv8::Tlv8;

    fn req(salt: &[u8]) -> Vec<u8> {
        Tlv8::new()
            .push_u8(1, 0)
            .push_u8(2, 0)
            .push(3, salt)
            .encode()
    }

    #[test]
    fn supported_config_shape() {
        assert_eq!(supported_config_tlv(), [1, 3, 1, 1, 0]);
    }

    #[tokio::test]
    async fn setup_response_tlv_shape_and_tcp_session() {
        let srv = HdsServer::new();
        let mut rx = srv.connections().unwrap();
        let secret = [3u8; 32];
        let csalt = [4u8; 32];
        let resp = srv
            .prepare(Some(secret), Ipv4Addr::LOCALHOST.into(), &req(&csalt))
            .await;
        let t = Tlv8::parse(&resp).unwrap();
        assert_eq!(t.get_u8(1).unwrap(), Some(0));
        let params = Tlv8::parse(t.get(2).unwrap()).unwrap();
        let port = params.get_u16(1).unwrap().unwrap();
        let asalt = t.get(3).unwrap();
        assert_eq!(asalt.len(), 32);

        // Simulated controller: derives keys with the received salt and sends hello over TCP.
        let acc = HdsKeys::derive(&secret, &csalt, asalt);
        let ctl = HdsKeys {
            encrypt: acc.decrypt,
            decrypt: acc.encrypt,
        };
        let sock = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut c = HdsConn::new(sock, ctl);
        let hello = DsValue::dict([
            ("protocol", DsValue::Str("control".into())),
            ("request", DsValue::Str("hello".into())),
            ("id", DsValue::Int(1)),
        ]);
        c.send_raw_for_test(hello, DsValue::Dict(vec![])).await;
        let mut srv_conn = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let m = c.next_message().await.unwrap();
        assert!(m.is(Kind::Response, "control", "hello"));
        srv_conn.send_close(1, 0).await.unwrap();
        assert!(
            c.next_message()
                .await
                .unwrap()
                .is(Kind::Event, "dataSend", "close")
        );
    }

    #[tokio::test]
    async fn setup_rejects_bad_requests() {
        let srv = HdsServer::new();
        let ip = Ipv4Addr::LOCALHOST.into();
        let err = |r: Vec<u8>| Tlv8::parse(&r).unwrap().get_u8(1).unwrap();
        assert_eq!(
            err(srv.prepare(Some([1; 32]), ip, &req(&[0; 31])).await),
            Some(1)
        );
        assert_eq!(err(srv.prepare(None, ip, &req(&[0; 32])).await), Some(1));
        let bad_cmd = Tlv8::new()
            .push_u8(1, 1)
            .push_u8(2, 0)
            .push(3, &[0; 32])
            .encode();
        assert_eq!(err(srv.prepare(Some([1; 32]), ip, &bad_cmd).await), Some(1));
        for _ in 0..MAX_PENDING {
            assert_eq!(
                err(srv.prepare(Some([1; 32]), ip, &req(&[0; 32])).await),
                Some(0)
            );
        }
        assert_eq!(
            err(srv.prepare(Some([1; 32]), ip, &req(&[0; 32])).await),
            Some(2)
        );
    }
}
