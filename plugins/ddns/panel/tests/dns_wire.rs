use super::*;

fn answer(id: u16, flags: [u8; 2], kind: u16, rdata: &[u8]) -> Vec<u8> {
    let mut packet = request(id, "node.example.com", kind).unwrap();
    packet[2..4].copy_from_slice(&flags);
    packet[6..8].copy_from_slice(&[0, 1]);
    packet.extend([0xc0, 0x0c]);
    packet.extend(kind.to_be_bytes());
    packet.extend([0, 1]);
    packet.extend(300u32.to_be_bytes());
    packet.extend((rdata.len() as u16).to_be_bytes());
    packet.extend(rdata);
    packet
}

#[test]
fn dns_response_matches_id_question_family_and_preserves_ttl_and_negative_evidence() {
    let packet = answer(7, [0x81, 0x80], 1, &[192, 0, 2, 1]);
    let result = response(&packet, 7, "node.example.com", 1).unwrap();
    assert_eq!(result["answers"][0]["value"], "192.0.2.1");
    assert_eq!(result["answers"][0]["ttl"], 300);
    assert_eq!(result["status"], "answered");
    assert!(response(&packet, 8, "node.example.com", 1).is_err());
    assert!(response(&packet, 7, "other.example.com", 1).is_err());
    assert!(response(&packet, 7, "node.example.com", 28).is_err());
    let mut missing = request(9, "node.example.com", 1).unwrap();
    missing[2] = 0x81;
    missing[3] = 0x83;
    let result = response(&missing, 9, "node.example.com", 1).unwrap();
    assert_eq!(result["status"], "nxdomain");
    assert_eq!(result["rcode"], 3);
    missing[3] = 0x80;
    assert_eq!(
        response(&missing, 9, "node.example.com", 1).unwrap()["status"],
        "no_data"
    );
}

#[test]
fn text_segments_are_joined_and_malformed_compression_or_lengths_are_rejected() {
    let packet = answer(7, [0x81, 0x80], 16, &[3, b'a', b'b', b'c', 2, b'd', b'e']);
    assert_eq!(
        response(&packet, 7, "node.example.com", 16).unwrap()["answers"][0]["value"],
        "abcde"
    );
    assert!(
        response(
            &answer(7, [0x81, 0x80], 16, &[20, b'a']),
            7,
            "node.example.com",
            16
        )
        .is_err()
    );
    assert!(
        response(
            &answer(7, [0x81, 0x80], 1, &[192, 0, 2]),
            7,
            "node.example.com",
            1
        )
        .is_err()
    );
    let mut at = 0;
    assert!(name(&[0xc0, 0], &mut at).is_err());
    let mut packet = packet;
    packet.truncate(packet.len() - 1);
    assert!(response(&packet, 7, "node.example.com", 16).is_err());
    assert!(request(1, "node..example.com", 1).is_none());
}

#[tokio::test]
async fn truncated_udp_reply_falls_back_to_same_explicit_resolver_over_tcp() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0u8; 512];
        let (length, source) = udp.recv_from(&mut bytes).await.unwrap();
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut truncated = bytes[..length].to_vec();
        truncated[2] = 0x83;
        truncated[3] = 0x80;
        udp.send_to(&truncated, source).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut query = vec![0u8; usize::from(length)];
        stream.read_exact(&mut query).await.unwrap();
        let response = answer(id, [0x81, 0x80], 1, &[192, 0, 2, 1]);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let input = super::super::dns_resolvers::Request {
        zone_id: "TEST_ONLY".into(),
        name: "node.example.com".into(),
        kind: "A".into(),
        resolver_ip: addr.ip(),
        resolver_port: addr.port(),
        expected: vec![],
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        super::super::dns_resolvers::query(&input, 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result["transport"], "tcp_fallback");
    assert_eq!(result["answers"][0]["value"], "192.0.2.1");
    server.await.unwrap();
}
