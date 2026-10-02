//! Minimal PPP for the FortiGate tunnel: LCP, IPCP and LCP echo keepalives.
//!
//! [`PppSession`] does no I/O. Feed it received frames with
//! [`handle`](PppSession::handle), call [`tick`](PppSession::tick) when
//! [`next_deadline`](PppSession::next_deadline) passes, then drain
//! [`poll_transmit`](PppSession::poll_transmit) and
//! [`poll_event`](PppSession::poll_event).

pub mod frame;
pub mod packet;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use packet::{
    CODE_REJECT, CONFIGURE_ACK, CONFIGURE_NAK, CONFIGURE_REJECT, CONFIGURE_REQUEST, ConfigOption,
    ControlPacket, DISCARD_REQUEST, ECHO_REPLY, ECHO_REQUEST, PROTOCOL_REJECT, TERMINATE_ACK,
    TERMINATE_REQUEST, encode_options, parse_options,
};

pub const PROTO_IPV4: u16 = 0x0021;
pub const PROTO_IPCP: u16 = 0x8021;
pub const PROTO_LCP: u16 = 0xc021;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;
const LCP_PFC: u8 = 7;
const LCP_ACFC: u8 = 8;
const IPCP_ADDRESS: u8 = 3;

pub const DEFAULT_MRU: u16 = 1354;

#[derive(Debug, Clone)]
pub struct PppConfig {
    pub mru: u16,
    /// Random LCP magic number, used in echo packets.
    pub magic: u32,
    /// Address to ask for in IPCP, normally the one from the XML config.
    pub requested_ip: Option<Ipv4Addr>,
    pub echo_interval: Duration,
    /// Unanswered echo requests before the link counts as dead.
    pub echo_failures: u32,
    pub restart_interval: Duration,
    pub max_configure: u32,
}

impl PppConfig {
    pub fn new(magic: u32, requested_ip: Option<Ipv4Addr>) -> Self {
        Self {
            mru: DEFAULT_MRU,
            magic,
            requested_ip,
            echo_interval: Duration::from_secs(10),
            echo_failures: 3,
            restart_interval: Duration::from_secs(3),
            max_configure: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PppEvent {
    /// IPCP finished; IP packets can flow.
    Up {
        local_ip: Ipv4Addr,
        peer_ip: Option<Ipv4Addr>,
    },
    /// An IPv4 packet from the gateway.
    Ip(Bytes),
    /// The session is over. No further events follow.
    Down(DownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownReason {
    PeerTerminated,
    EchoTimeout,
    NegotiationFailed,
    LocalClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layer {
    Lcp,
    Ipcp,
}

impl Layer {
    fn protocol(self) -> u16 {
        match self {
            Layer::Lcp => PROTO_LCP,
            Layer::Ipcp => PROTO_IPCP,
        }
    }
}

#[derive(Debug)]
struct Negotiation {
    options: Vec<ConfigOption>,
    request_id: u8,
    we_acked: bool,
    they_acked: bool,
    retransmit_at: Option<Instant>,
    attempts: u32,
}

impl Negotiation {
    fn new(options: Vec<ConfigOption>) -> Self {
        Self {
            options,
            request_id: 0,
            we_acked: false,
            they_acked: false,
            retransmit_at: None,
            attempts: 0,
        }
    }

    fn opened(&self) -> bool {
        self.we_acked && self.they_acked
    }

    fn set_option(&mut self, opt: ConfigOption) {
        match self.options.iter_mut().find(|o| o.kind == opt.kind) {
            Some(existing) => *existing = opt,
            None => self.options.push(opt),
        }
    }
}

#[derive(Debug)]
pub struct PppSession {
    cfg: PppConfig,
    lcp: Negotiation,
    ipcp: Option<Negotiation>,
    peer_ip: Option<Ipv4Addr>,
    up: bool,
    dead: bool,
    closing_deadline: Option<Instant>,
    next_echo: Option<Instant>,
    echo_outstanding: u32,
    next_id: u8,
    outbox: VecDeque<(u16, Bytes)>,
    events: VecDeque<PppEvent>,
}

impl PppSession {
    /// Starts LCP negotiation. The first Configure-Request is queued.
    pub fn new(cfg: PppConfig, now: Instant) -> Self {
        let lcp = Negotiation::new(vec![
            ConfigOption::new(LCP_MRU, cfg.mru.to_be_bytes().to_vec()),
            ConfigOption::new(LCP_MAGIC, cfg.magic.to_be_bytes().to_vec()),
        ]);
        let mut session = Self {
            cfg,
            lcp,
            ipcp: None,
            peer_ip: None,
            up: false,
            dead: false,
            closing_deadline: None,
            next_echo: None,
            echo_outstanding: 0,
            next_id: 1,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        };
        session.send_configure_request(Layer::Lcp, now);
        session
    }

    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Next frame to send: `(protocol, information field)`.
    pub fn poll_transmit(&mut self) -> Option<(u16, Bytes)> {
        self.outbox.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<PppEvent> {
        self.events.pop_front()
    }

    /// When [`tick`](Self::tick) next needs to run.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.dead {
            return None;
        }
        if let Some(deadline) = self.closing_deadline {
            return Some(deadline);
        }
        [
            self.lcp.retransmit_at,
            self.ipcp.as_ref().and_then(|n| n.retransmit_at),
            self.next_echo,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Queues an IPv4 packet for the gateway. Returns `false` (and drops the
    /// packet) while the link is not up.
    pub fn send_ip(&mut self, packet: Bytes) -> bool {
        if self.up && !self.dead {
            self.outbox.push_back((PROTO_IPV4, packet));
            true
        } else {
            false
        }
    }

    /// Asks the gateway to end the session. [`PppEvent::Down`] follows once
    /// it acknowledges or after a short timeout.
    pub fn close(&mut self, now: Instant) {
        if self.dead || self.closing_deadline.is_some() {
            return;
        }
        self.up = false;
        let id = self.alloc_id();
        self.push_control(
            Layer::Lcp,
            ControlPacket::new(TERMINATE_REQUEST, id, Bytes::new()),
        );
        self.closing_deadline = Some(now + self.cfg.restart_interval);
    }

    pub fn handle(&mut self, protocol: u16, payload: Bytes, now: Instant) {
        if self.dead {
            return;
        }
        // Any traffic from the gateway proves the link is alive.
        self.echo_outstanding = 0;

        match protocol {
            PROTO_LCP => self.handle_lcp(payload, now),
            PROTO_IPCP if self.lcp.opened() => self.handle_ipcp(payload, now),
            PROTO_IPV4 if self.up => self.events.push_back(PppEvent::Ip(payload)),
            PROTO_IPCP | PROTO_IPV4 => {}
            other if self.lcp.opened() => {
                tracing::debug!(
                    protocol = format_args!("{other:#06x}"),
                    "rejecting unsupported PPP protocol"
                );
                let mut data = BytesMut::with_capacity(2 + payload.len());
                data.put_u16(other);
                data.put_slice(&payload[..payload.len().min(self.cfg.mru as usize - 8)]);
                let id = self.alloc_id();
                self.push_control(
                    Layer::Lcp,
                    ControlPacket::new(PROTOCOL_REJECT, id, data.freeze()),
                );
            }
            _ => {}
        }
    }

    pub fn tick(&mut self, now: Instant) {
        if self.dead {
            return;
        }
        if let Some(deadline) = self.closing_deadline {
            if now >= deadline {
                self.go_down(DownReason::LocalClose);
            }
            return;
        }

        for layer in [Layer::Lcp, Layer::Ipcp] {
            let Some(neg) = self.negotiation(layer) else {
                continue;
            };
            if neg.they_acked || neg.retransmit_at.is_none_or(|t| now < t) {
                continue;
            }
            if neg.attempts >= self.cfg.max_configure {
                tracing::warn!(?layer, "gateway never acknowledged our configuration");
                self.go_down(DownReason::NegotiationFailed);
                return;
            }
            self.send_configure_request(layer, now);
        }

        if let Some(at) = self.next_echo
            && now >= at
        {
            if self.echo_outstanding >= self.cfg.echo_failures {
                self.go_down(DownReason::EchoTimeout);
                return;
            }
            self.echo_outstanding += 1;
            let id = self.alloc_id();
            let magic = self.cfg.magic.to_be_bytes().to_vec();
            self.push_control(Layer::Lcp, ControlPacket::new(ECHO_REQUEST, id, magic));
            self.next_echo = Some(now + self.cfg.echo_interval);
        }
    }

    fn handle_lcp(&mut self, payload: Bytes, now: Instant) {
        let Some(pkt) = ControlPacket::parse(&payload) else {
            return;
        };
        match pkt.code {
            CONFIGURE_REQUEST => {
                if self.lcp.opened() {
                    tracing::info!("gateway restarted LCP negotiation");
                    self.restart_lcp(now);
                }
                let Some(options) = parse_options(&pkt.data) else {
                    return;
                };
                let rejected: Vec<_> = options
                    .into_iter()
                    .filter(|o| !lcp_option_acceptable(o))
                    .collect();
                if rejected.is_empty() {
                    self.lcp.we_acked = true;
                    self.push_control(
                        Layer::Lcp,
                        ControlPacket::new(CONFIGURE_ACK, pkt.id, pkt.data),
                    );
                    self.lcp_maybe_opened(now);
                } else {
                    self.lcp.we_acked = false;
                    let data = encode_options(&rejected);
                    self.push_control(
                        Layer::Lcp,
                        ControlPacket::new(CONFIGURE_REJECT, pkt.id, data),
                    );
                }
            }
            CONFIGURE_ACK if pkt.id == self.lcp.request_id && !self.lcp.they_acked => {
                self.lcp.they_acked = true;
                self.lcp.retransmit_at = None;
                self.lcp_maybe_opened(now);
            }
            CONFIGURE_NAK if pkt.id == self.lcp.request_id => {
                for opt in parse_options(&pkt.data).unwrap_or_default() {
                    match opt.kind {
                        LCP_MRU if opt.u16().is_some() => self.lcp.set_option(opt),
                        LCP_MAGIC => {
                            self.cfg.magic = self.cfg.magic.rotate_left(7) ^ 0x5a5a_5a5a;
                            let magic = self.cfg.magic.to_be_bytes().to_vec();
                            self.lcp.set_option(ConfigOption::new(LCP_MAGIC, magic));
                        }
                        _ => {}
                    }
                }
                self.send_configure_request(Layer::Lcp, now);
            }
            CONFIGURE_REJECT if pkt.id == self.lcp.request_id => {
                let rejected: Vec<u8> = parse_options(&pkt.data)
                    .unwrap_or_default()
                    .iter()
                    .map(|o| o.kind)
                    .collect();
                self.lcp.options.retain(|o| !rejected.contains(&o.kind));
                self.send_configure_request(Layer::Lcp, now);
            }
            TERMINATE_REQUEST => {
                self.push_control(
                    Layer::Lcp,
                    ControlPacket::new(TERMINATE_ACK, pkt.id, Bytes::new()),
                );
                self.go_down(DownReason::PeerTerminated);
            }
            TERMINATE_ACK if self.closing_deadline.is_some() => {
                self.go_down(DownReason::LocalClose)
            }
            ECHO_REQUEST if self.lcp.opened() => {
                let mut data = BytesMut::with_capacity(pkt.data.len().max(4));
                data.put_u32(self.cfg.magic);
                if pkt.data.len() > 4 {
                    data.put_slice(&pkt.data[4..]);
                }
                self.push_control(
                    Layer::Lcp,
                    ControlPacket::new(ECHO_REPLY, pkt.id, data.freeze()),
                );
            }
            PROTOCOL_REJECT if pkt.data.starts_with(&PROTO_IPCP.to_be_bytes()) => {
                tracing::warn!("gateway rejected IPCP");
                self.go_down(DownReason::NegotiationFailed);
            }
            CONFIGURE_ACK | CONFIGURE_NAK | CONFIGURE_REJECT | TERMINATE_ACK | ECHO_REQUEST
            | ECHO_REPLY | DISCARD_REQUEST | PROTOCOL_REJECT | CODE_REJECT => {}
            _ => self.code_reject(Layer::Lcp, &payload),
        }
    }

    fn handle_ipcp(&mut self, payload: Bytes, now: Instant) {
        let Some(pkt) = ControlPacket::parse(&payload) else {
            return;
        };
        let Some(ipcp) = self.ipcp.as_mut() else {
            return;
        };
        match pkt.code {
            CONFIGURE_REQUEST => {
                if ipcp.opened() {
                    tracing::info!("gateway restarted IPCP negotiation");
                    ipcp.they_acked = false;
                    self.up = false;
                    self.send_configure_request(Layer::Ipcp, now);
                }
                let Some(options) = parse_options(&pkt.data) else {
                    return;
                };
                let (accepted, rejected): (Vec<_>, Vec<_>) = options
                    .into_iter()
                    .partition(|o| o.kind == IPCP_ADDRESS && o.data.len() == 4);
                let ipcp = self.ipcp.as_mut().expect("ipcp present");
                if rejected.is_empty() {
                    ipcp.we_acked = true;
                    self.peer_ip = accepted.first().and_then(|o| o.u32()).map(Ipv4Addr::from);
                    self.push_control(
                        Layer::Ipcp,
                        ControlPacket::new(CONFIGURE_ACK, pkt.id, pkt.data),
                    );
                    self.ipcp_maybe_up();
                } else {
                    ipcp.we_acked = false;
                    let data = encode_options(&rejected);
                    self.push_control(
                        Layer::Ipcp,
                        ControlPacket::new(CONFIGURE_REJECT, pkt.id, data),
                    );
                }
            }
            CONFIGURE_ACK if pkt.id == ipcp.request_id && !ipcp.they_acked => {
                ipcp.they_acked = true;
                ipcp.retransmit_at = None;
                self.ipcp_maybe_up();
            }
            CONFIGURE_NAK if pkt.id == ipcp.request_id => {
                for opt in parse_options(&pkt.data).unwrap_or_default() {
                    if opt.kind == IPCP_ADDRESS && opt.data.len() == 4 {
                        ipcp.set_option(opt);
                    }
                }
                self.send_configure_request(Layer::Ipcp, now);
            }
            CONFIGURE_REJECT if pkt.id == ipcp.request_id => {
                let rejected: Vec<u8> = parse_options(&pkt.data)
                    .unwrap_or_default()
                    .iter()
                    .map(|o| o.kind)
                    .collect();
                ipcp.options.retain(|o| !rejected.contains(&o.kind));
                self.send_configure_request(Layer::Ipcp, now);
            }
            TERMINATE_REQUEST => {
                self.push_control(
                    Layer::Ipcp,
                    ControlPacket::new(TERMINATE_ACK, pkt.id, Bytes::new()),
                );
                self.go_down(DownReason::PeerTerminated);
            }
            CONFIGURE_ACK | CONFIGURE_NAK | CONFIGURE_REJECT | TERMINATE_ACK | CODE_REJECT => {}
            _ => self.code_reject(Layer::Ipcp, &payload),
        }
    }

    fn lcp_maybe_opened(&mut self, now: Instant) {
        if !self.lcp.opened() || self.ipcp.is_some() {
            return;
        }
        tracing::debug!("LCP opened");
        let ip = self.cfg.requested_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.ipcp = Some(Negotiation::new(vec![ConfigOption::new(
            IPCP_ADDRESS,
            ip.octets().to_vec(),
        )]));
        self.send_configure_request(Layer::Ipcp, now);
        self.next_echo = Some(now + self.cfg.echo_interval);
    }

    fn ipcp_maybe_up(&mut self) {
        let Some(ipcp) = &self.ipcp else { return };
        if !ipcp.opened() || self.up {
            return;
        }
        let negotiated = ipcp
            .options
            .iter()
            .find(|o| o.kind == IPCP_ADDRESS)
            .and_then(ConfigOption::u32)
            .map(Ipv4Addr::from)
            .filter(|ip| !ip.is_unspecified());
        let Some(local_ip) = negotiated.or(self.cfg.requested_ip) else {
            tracing::warn!("IPCP finished without an address for us");
            self.go_down(DownReason::NegotiationFailed);
            return;
        };
        tracing::debug!(%local_ip, peer_ip = ?self.peer_ip, "IPCP opened");
        self.up = true;
        self.events.push_back(PppEvent::Up {
            local_ip,
            peer_ip: self.peer_ip,
        });
    }

    fn restart_lcp(&mut self, now: Instant) {
        self.lcp.we_acked = false;
        self.lcp.they_acked = false;
        self.lcp.attempts = 0;
        self.ipcp = None;
        self.up = false;
        self.next_echo = None;
        self.send_configure_request(Layer::Lcp, now);
    }

    fn negotiation(&mut self, layer: Layer) -> Option<&mut Negotiation> {
        match layer {
            Layer::Lcp => Some(&mut self.lcp),
            Layer::Ipcp => self.ipcp.as_mut(),
        }
    }

    fn send_configure_request(&mut self, layer: Layer, now: Instant) {
        let id = self.alloc_id();
        let restart = self.cfg.restart_interval;
        let Some(neg) = self.negotiation(layer) else {
            return;
        };
        neg.request_id = id;
        neg.attempts += 1;
        neg.retransmit_at = Some(now + restart);
        let data = encode_options(&neg.options);
        self.push_control(layer, ControlPacket::new(CONFIGURE_REQUEST, id, data));
    }

    fn code_reject(&mut self, layer: Layer, rejected: &Bytes) {
        let id = self.alloc_id();
        let max = self.cfg.mru as usize - 4;
        let data = rejected.slice(..rejected.len().min(max));
        self.push_control(layer, ControlPacket::new(CODE_REJECT, id, data));
    }

    fn push_control(&mut self, layer: Layer, pkt: ControlPacket) {
        self.outbox.push_back((layer.protocol(), pkt.encode()));
    }

    fn alloc_id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn go_down(&mut self, reason: DownReason) {
        if self.dead {
            return;
        }
        tracing::debug!(?reason, "PPP down");
        self.dead = true;
        self.up = false;
        self.events.push_back(PppEvent::Down(reason));
    }
}

fn lcp_option_acceptable(opt: &ConfigOption) -> bool {
    match opt.kind {
        LCP_MRU => opt.data.len() == 2,
        LCP_ACCM | LCP_MAGIC => opt.data.len() == 4,
        LCP_PFC | LCP_ACFC => opt.data.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
