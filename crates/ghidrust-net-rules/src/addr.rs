//! IPv4 / CIDR / list / port matching for Suricata-style headers.

pub fn ipv4_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    let mut o = [0u8; 4];
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        o[i] = p.parse().ok()?;
    }
    Some(u32::from_be_bytes(o))
}

pub fn cidr_contains(cidr: &str, ip: &str) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n.trim(), b.trim().parse::<u32>().unwrap_or(32).min(32)),
        None => return ipv4_u32(cidr) == ipv4_u32(ip),
    };
    let Some(n) = ipv4_u32(net) else {
        return false;
    };
    let Some(a) = ipv4_u32(ip) else {
        return false;
    };
    if bits == 0 {
        return true;
    }
    let mask = !0u32 << (32 - bits);
    (n & mask) == (a & mask)
}

/// Match a Suricata address atom: `any`, IP, CIDR, `!atom`, `[a,b,c]`.
pub fn addr_matches(pat: &str, addr: &str) -> bool {
    let pat = pat.trim();
    if pat.is_empty() || pat.eq_ignore_ascii_case("any") {
        return true;
    }
    if let Some(rest) = pat.strip_prefix('!') {
        return !addr_matches(rest.trim(), addr);
    }
    if pat.starts_with('[') && pat.ends_with(']') {
        let inner = &pat[1..pat.len() - 1];
        return split_list(inner).iter().any(|t| addr_matches(t, addr));
    }
    if pat.contains('/') {
        return cidr_contains(pat, addr);
    }
    pat == addr || ipv4_u32(pat) == ipv4_u32(addr)
}

pub fn port_matches(pat: &str, port: u16) -> bool {
    let pat = pat.trim();
    if pat.is_empty() || pat.eq_ignore_ascii_case("any") {
        return true;
    }
    if let Some(rest) = pat.strip_prefix('!') {
        return !port_matches(rest.trim(), port);
    }
    if pat.starts_with('[') && pat.ends_with(']') {
        let inner = &pat[1..pat.len() - 1];
        return split_list(inner).iter().any(|t| port_matches(t, port));
    }
    if let Some((a, b)) = pat.split_once(':') {
        let lo: u16 = a.parse().unwrap_or(0);
        let hi: u16 = b.parse().unwrap_or(65535);
        return port >= lo && port <= hi;
    }
    pat.parse::<u16>().ok() == Some(port)
}

pub fn split_list(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in inner.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_list_and_negation() {
        assert!(addr_matches("10.0.0.0/8", "10.1.2.3"));
        assert!(!addr_matches("10.0.0.0/8", "11.0.0.1"));
        assert!(addr_matches("[1.2.3.4, 10.0.0.0/8]", "10.9.9.9"));
        assert!(!addr_matches("!10.0.0.1", "10.0.0.1"));
        assert!(addr_matches("any", "8.8.8.8"));
        assert!(port_matches("[80,443]", 443));
        assert!(port_matches("8000:8010", 8005));
        assert!(!port_matches("80", 81));
    }
}
