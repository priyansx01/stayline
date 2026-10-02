use super::*;

const MAGIC: u32 = 0x1122_3344;
const ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 212, 134, 200);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 2, 1);

fn opt(kind: u8, data: &[u8]) -> ConfigOption {
    ConfigOption::new(kind, data.to_vec())
}

fn control(code: u8, id: u8, options: &[ConfigOption]) -> Bytes {
    ControlPacket::new(code, id, encode_options(options)).encode()
}

/// Drains everything the session wants to send, as parsed control packets.
fn sent(s: &mut PppSession) -> Vec<(u16, ControlPacket)> {
    std::iter::from_fn(|| s.poll_transmit())
        .map(|(proto, data)| {
            let pkt = if proto == PROTO_IPV4 {
                ControlPacket::new(0, 0, data)
            } else {
                ControlPacket::parse(&data).expect("valid control packet")
            };
            (proto, pkt)
        })
        .collect()
}

fn events(s: &mut PppSession) -> Vec<PppEvent> {
    std::iter::from_fn(|| s.poll_event()).collect()
}

fn find(packets: &[(u16, ControlPacket)], proto: u16, code: u8) -> ControlPacket {
    packets
        .iter()
        .find(|(p, pkt)| *p == proto && pkt.code == code)
        .map(|(_, pkt)| pkt.clone())
        .unwrap_or_else(|| panic!("no packet {proto:#06x}/{code} in {packets:?}"))
}

/// Brings a session to LCP-opened, returning it and our IPCP request.
fn lcp_opened(now: Instant) -> (PppSession, ControlPacket) {
    let mut s = PppSession::new(PppConfig::new(MAGIC, Some(ASSIGNED)), now);
    let our_req = find(&sent(&mut s), PROTO_LCP, CONFIGURE_REQUEST);

    let peer_opts = [
        opt(LCP_MRU, &1354u16.to_be_bytes()),
        opt(LCP_MAGIC, &[9, 9, 9, 9]),
        opt(LCP_ACCM, &[0; 4]),
    ];
    s.handle(PROTO_LCP, control(CONFIGURE_REQUEST, 1, &peer_opts), now);
    s.handle(
        PROTO_LCP,
        ControlPacket::new(CONFIGURE_ACK, our_req.id, our_req.data).encode(),
        now,
    );

    let out = sent(&mut s);
    let ack = find(&out, PROTO_LCP, CONFIGURE_ACK);
    assert_eq!(ack.id, 1);
    assert_eq!(parse_options(&ack.data).unwrap(), peer_opts);
    let ipcp_req = find(&out, PROTO_IPCP, CONFIGURE_REQUEST);
    (s, ipcp_req)
}

fn up(now: Instant) -> PppSession {
    let (mut s, ipcp_req) = lcp_opened(now);
    s.handle(
        PROTO_IPCP,
        control(
            CONFIGURE_REQUEST,
            1,
            &[opt(IPCP_ADDRESS, &GATEWAY_IP.octets())],
        ),
        now,
    );
    s.handle(
        PROTO_IPCP,
        ControlPacket::new(CONFIGURE_ACK, ipcp_req.id, ipcp_req.data).encode(),
        now,
    );
    sent(&mut s);
    assert_eq!(
        events(&mut s),
        vec![PppEvent::Up {
            local_ip: ASSIGNED,
            peer_ip: Some(GATEWAY_IP)
        }]
    );
    s
}

#[test]
fn first_lcp_request_carries_mru_and_magic() {
    let mut s = PppSession::new(PppConfig::new(MAGIC, None), Instant::now());
    let req = find(&sent(&mut s), PROTO_LCP, CONFIGURE_REQUEST);
    assert_eq!(
        parse_options(&req.data).unwrap(),
        vec![
            opt(LCP_MRU, &1354u16.to_be_bytes()),
            opt(LCP_MAGIC, &MAGIC.to_be_bytes())
        ]
    );
}

#[test]
fn ipcp_asks_for_the_assigned_address() {
    let (_, ipcp_req) = lcp_opened(Instant::now());
    assert_eq!(
        parse_options(&ipcp_req.data).unwrap(),
        vec![opt(IPCP_ADDRESS, &ASSIGNED.octets())]
    );
}

#[test]
fn full_handshake_brings_link_up() {
    up(Instant::now());
}

#[test]
fn ipcp_nak_address_is_adopted() {
    let now = Instant::now();
    let (mut s, ipcp_req) = lcp_opened(now);
    let offered = Ipv4Addr::new(10, 1, 2, 3);
    s.handle(
        PROTO_IPCP,
        control(
            CONFIGURE_NAK,
            ipcp_req.id,
            &[opt(IPCP_ADDRESS, &offered.octets())],
        ),
        now,
    );
    let retry = find(&sent(&mut s), PROTO_IPCP, CONFIGURE_REQUEST);
    assert_ne!(retry.id, ipcp_req.id);
    assert_eq!(
        parse_options(&retry.data).unwrap(),
        vec![opt(IPCP_ADDRESS, &offered.octets())]
    );

    s.handle(
        PROTO_IPCP,
        control(
            CONFIGURE_REQUEST,
            7,
            &[opt(IPCP_ADDRESS, &GATEWAY_IP.octets())],
        ),
        now,
    );
    s.handle(
        PROTO_IPCP,
        ControlPacket::new(CONFIGURE_ACK, retry.id, retry.data).encode(),
        now,
    );
    assert!(events(&mut s).contains(&PppEvent::Up {
        local_ip: offered,
        peer_ip: Some(GATEWAY_IP)
    }));
}

#[test]
fn unknown_lcp_options_are_rejected() {
    let now = Instant::now();
    let mut s = PppSession::new(PppConfig::new(MAGIC, None), now);
    sent(&mut s);
    let auth_pap = opt(3, &[0xc0, 0x23]);
    s.handle(
        PROTO_LCP,
        control(
            CONFIGURE_REQUEST,
            4,
            &[opt(LCP_MAGIC, &[1, 2, 3, 4]), auth_pap.clone()],
        ),
        now,
    );
    let rej = find(&sent(&mut s), PROTO_LCP, CONFIGURE_REJECT);
    assert_eq!(rej.id, 4);
    assert_eq!(parse_options(&rej.data).unwrap(), vec![auth_pap]);
}

#[test]
fn rejected_options_are_dropped_from_our_request() {
    let now = Instant::now();
    let mut s = PppSession::new(PppConfig::new(MAGIC, None), now);
    let req = find(&sent(&mut s), PROTO_LCP, CONFIGURE_REQUEST);
    s.handle(
        PROTO_LCP,
        control(
            CONFIGURE_REJECT,
            req.id,
            &[opt(LCP_MRU, &1354u16.to_be_bytes())],
        ),
        now,
    );
    let retry = find(&sent(&mut s), PROTO_LCP, CONFIGURE_REQUEST);
    assert_eq!(
        parse_options(&retry.data).unwrap(),
        vec![opt(LCP_MAGIC, &MAGIC.to_be_bytes())]
    );
}

#[test]
fn ip_packets_flow_only_when_up() {
    let now = Instant::now();
    let (mut s, _) = lcp_opened(now);
    assert!(!s.send_ip(Bytes::from_static(&[0x45, 0])));
    s.handle(PROTO_IPV4, Bytes::from_static(&[0x45, 1]), now);
    assert!(events(&mut s).is_empty());

    let mut s = up(now);
    assert!(s.send_ip(Bytes::from_static(&[0x45, 2])));
    assert_eq!(
        s.poll_transmit(),
        Some((PROTO_IPV4, Bytes::from_static(&[0x45, 2])))
    );
    s.handle(PROTO_IPV4, Bytes::from_static(&[0x45, 3]), now);
    assert_eq!(
        events(&mut s),
        vec![PppEvent::Ip(Bytes::from_static(&[0x45, 3]))]
    );
}

#[test]
fn answers_echo_with_our_magic() {
    let now = Instant::now();
    let mut s = up(now);
    let req = ControlPacket::new(ECHO_REQUEST, 42, vec![9, 9, 9, 9, 0xab]).encode();
    s.handle(PROTO_LCP, req, now);
    let reply = find(&sent(&mut s), PROTO_LCP, ECHO_REPLY);
    assert_eq!(reply.id, 42);
    assert_eq!(&reply.data[..], &[0x11, 0x22, 0x33, 0x44, 0xab]);
}

#[test]
fn three_missed_echoes_take_the_link_down() {
    let start = Instant::now();
    let mut s = up(start);
    let interval = Duration::from_secs(10);

    for n in 1..=3 {
        s.tick(start + interval * n);
        let echo = find(&sent(&mut s), PROTO_LCP, ECHO_REQUEST);
        assert_eq!(&echo.data[..], &MAGIC.to_be_bytes());
        assert!(events(&mut s).is_empty(), "down too early after {n} echoes");
    }
    s.tick(start + interval * 4);
    assert_eq!(
        events(&mut s),
        vec![PppEvent::Down(DownReason::EchoTimeout)]
    );
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn any_traffic_resets_echo_misses() {
    let start = Instant::now();
    let mut s = up(start);
    let interval = Duration::from_secs(10);
    for n in 1..=10 {
        s.tick(start + interval * n);
        sent(&mut s);
        s.handle(
            PROTO_IPV4,
            Bytes::from_static(&[0x45]),
            start + interval * n,
        );
    }
    assert!(
        !events(&mut s)
            .iter()
            .any(|e| matches!(e, PppEvent::Down(_)))
    );
}

#[test]
fn peer_terminate_is_acked_and_ends_session() {
    let now = Instant::now();
    let mut s = up(now);
    s.handle(
        PROTO_LCP,
        ControlPacket::new(TERMINATE_REQUEST, 5, Bytes::new()).encode(),
        now,
    );
    let ack = find(&sent(&mut s), PROTO_LCP, TERMINATE_ACK);
    assert_eq!(ack.id, 5);
    assert_eq!(
        events(&mut s),
        vec![PppEvent::Down(DownReason::PeerTerminated)]
    );
    assert!(!s.send_ip(Bytes::from_static(&[0x45])));
}

#[test]
fn local_close_waits_for_ack() {
    let now = Instant::now();
    let mut s = up(now);
    s.close(now);
    find(&sent(&mut s), PROTO_LCP, TERMINATE_REQUEST);
    assert!(events(&mut s).is_empty());
    s.handle(
        PROTO_LCP,
        ControlPacket::new(TERMINATE_ACK, 1, Bytes::new()).encode(),
        now,
    );
    assert_eq!(events(&mut s), vec![PppEvent::Down(DownReason::LocalClose)]);
}

#[test]
fn local_close_times_out_without_ack() {
    let now = Instant::now();
    let mut s = up(now);
    s.close(now);
    s.tick(now + Duration::from_secs(5));
    assert_eq!(events(&mut s), vec![PppEvent::Down(DownReason::LocalClose)]);
}

#[test]
fn configure_request_is_retransmitted_then_gives_up() {
    let start = Instant::now();
    let mut s = PppSession::new(PppConfig::new(MAGIC, None), start);
    sent(&mut s);
    for n in 1..10 {
        s.tick(start + Duration::from_secs(3 * n));
        find(&sent(&mut s), PROTO_LCP, CONFIGURE_REQUEST);
    }
    s.tick(start + Duration::from_secs(30));
    assert_eq!(
        events(&mut s),
        vec![PppEvent::Down(DownReason::NegotiationFailed)]
    );
}

#[test]
fn unsupported_protocols_get_protocol_reject() {
    let now = Instant::now();
    let mut s = up(now);
    s.handle(0x8057, Bytes::from_static(&[1, 1, 0, 4]), now);
    let rej = find(&sent(&mut s), PROTO_LCP, PROTOCOL_REJECT);
    assert_eq!(&rej.data[..], &[0x80, 0x57, 1, 1, 0, 4]);
}

#[test]
fn unknown_lcp_code_gets_code_reject() {
    let now = Instant::now();
    let mut s = up(now);
    s.handle(PROTO_LCP, ControlPacket::new(99, 3, vec![1]).encode(), now);
    find(&sent(&mut s), PROTO_LCP, CODE_REJECT);
}

#[test]
fn lcp_renegotiation_pauses_ip_until_up_again() {
    let now = Instant::now();
    let mut s = up(now);
    s.handle(
        PROTO_LCP,
        control(CONFIGURE_REQUEST, 20, &[opt(LCP_MAGIC, &[7, 7, 7, 7])]),
        now,
    );
    assert!(!s.is_up());
    let out = sent(&mut s);
    find(&out, PROTO_LCP, CONFIGURE_REQUEST);
    find(&out, PROTO_LCP, CONFIGURE_ACK);
    assert!(!s.send_ip(Bytes::from_static(&[0x45])));
}
