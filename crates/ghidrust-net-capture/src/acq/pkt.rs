//! L2/L3 frame decode (libpcap/Npcap packet layout as reference; no pcap crate).
//!
//! Ethernet (14) or raw IPv4 (SIO_RCVALL) → [`ghidrust_net_flow::Frame`].

use ghidrust_net_flow::Frame;

pub fn decode_packet(ts_ms: u64, bytes: &[u8]) -> Option<Frame> {
    if bytes.len() >= 14 && is_ethertype_ip(&bytes[12..14]) {
        return decode_l3(ts_ms, &bytes[14..]);
    }
    if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
        return decode_l3(ts_ms, bytes);
    }
    None
}

fn is_ethertype_ip(et: &[u8]) -> bool {
    et == [0x08, 0x00] || et == [0x86, 0xdd]
}

fn decode_l3(ts_ms: u64, ip: &[u8]) -> Option<Frame> {
    if ip.len() < 20 {
        return None;
    }
    let ver = ip[0] >> 4;
    if ver == 4 {
        decode_ipv4(ts_ms, ip)
    } else {
        None
    }
}

fn decode_ipv4(ts_ms: u64, ip: &[u8]) -> Option<Frame> {
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let proto_n = ip[9];
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let rest = &ip[ihl..];
    let (proto, src_port, dst_port, payload, tcp_seq, tcp_ack, tcp_flags) = match proto_n {
        6 if rest.len() >= 20 => {
            let sp = u16::from_be_bytes([rest[0], rest[1]]);
            let dp = u16::from_be_bytes([rest[2], rest[3]]);
            let seq = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
            let ack = u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]);
            let doff = ((rest[12] >> 4) as usize) * 4;
            let flags = rest[13];
            let pay = if rest.len() > doff {
                rest[doff..].to_vec()
            } else {
                Vec::new()
            };
            ("tcp", sp, dp, pay, Some(seq), Some(ack), Some(flags))
        }
        17 if rest.len() >= 8 => {
            let sp = u16::from_be_bytes([rest[0], rest[1]]);
            let dp = u16::from_be_bytes([rest[2], rest[3]]);
            ("udp", sp, dp, rest[8..].to_vec(), None, None, None)
        }
        1 => ("icmp", 0, 0, rest.to_vec(), None, None, None),
        other => {
            let name = match other {
                47 => "gre",
                50 => "esp",
                _ => "ip",
            };
            (name, 0, 0, rest.to_vec(), None, None, None)
        }
    };
    Some(Frame {
        ts_ms,
        proto: proto.into(),
        src,
        dst,
        src_port,
        dst_port,
        payload,
        tcp_seq,
        tcp_ack,
        tcp_flags,
        owner: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_raw_ipv4_tcp() {
        // IPv4 20 + TCP 20 + "HI"
        let mut pkt = vec![0u8; 42];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20] = 0x04;
        pkt[21] = 0xd2; // 1234
        pkt[22] = 0x00;
        pkt[23] = 80;
        pkt[32] = 0x50; // data offset 5
        pkt[40] = b'H';
        pkt[41] = b'I';
        let f = decode_packet(1, &pkt).expect("frame");
        assert_eq!(f.proto, "tcp");
        assert_eq!(f.src, "10.0.0.1");
        assert_eq!(f.dst, "10.0.0.2");
        assert_eq!(f.src_port, 1234);
        assert_eq!(f.dst_port, 80);
        assert_eq!(f.payload, b"HI");
    }

    #[test]
    fn decodes_ethernet_ipv4() {
        let mut pkt = vec![0u8; 14 + 28];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[14 + 9] = 17; // UDP
        pkt[14 + 12..14 + 16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[14 + 16..14 + 20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[14 + 20] = 0x00;
        pkt[14 + 21] = 53;
        pkt[14 + 22] = 0x00;
        pkt[14 + 23] = 53;
        let f = decode_packet(2, &pkt).expect("eth");
        assert_eq!(f.proto, "udp");
        assert_eq!(f.src_port, 53);
        assert_eq!(f.dst_port, 53);
    }
}
