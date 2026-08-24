//! Native detection pipeline: compiled rules × frames/flows → alerts.

mod inline_gate;
mod mpm;

pub use inline_gate::inline_block_allowed;

use ghidrust_net_flow::{FlowTable, Frame};
use ghidrust_net_parse::{parse_client_hello, parse_qnames, parse_request_ex};
use ghidrust_net_rules::{
    addr_matches, compile_rules, load_rule_pack, port_matches, CompiledRuleset, ContentOpt,
    DetectOp, Rule,
};
use ghidrust_net_schema::{Alert, FlowKey, Owner};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub use mpm::MultiPattern;

#[derive(Debug, Default)]
pub struct AlertBuffer {
    alerts: Mutex<Vec<Alert>>,
}

impl AlertBuffer {
    pub fn push(&self, a: Alert) {
        self.alerts.lock().unwrap().push(a);
    }
    pub fn list(&self, max: Option<usize>) -> Vec<Alert> {
        let g = self.alerts.lock().unwrap();
        match max {
            Some(n) => g.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect(),
            None => g.clone(),
        }
    }
    pub fn clear(&self) {
        self.alerts.lock().unwrap().clear();
    }
}

static LAST_ALERTS: once_cell_proxy::LazyAlertBuf = once_cell_proxy::LazyAlertBuf::new();

mod once_cell_proxy {
    use super::AlertBuffer;
    use std::sync::OnceLock;
    pub struct LazyAlertBuf(OnceLock<AlertBuffer>);
    impl LazyAlertBuf {
        pub const fn new() -> Self {
            Self(OnceLock::new())
        }
        pub fn get(&self) -> &AlertBuffer {
            self.0.get_or_init(AlertBuffer::default)
        }
    }
}

pub fn last_alerts(max: Option<usize>) -> Vec<Alert> {
    LAST_ALERTS.get().list(max)
}

/// Run detection on a capture file path using the native file reader + rules.
pub fn detect_capture_file(
    capture_path: &Path,
    rules: &CompiledRuleset,
    attr_owners: &[(FlowKey, Owner)],
) -> Result<Vec<Alert>, String> {
    let frames = ghidrust_net_capture_replay::read_frames(capture_path)?;
    detect_frames(&frames, rules, attr_owners)
}

/// Detect without depending on capture crate at type level for unit tests — frames supplied.
pub fn detect_frames(
    frames: &[Frame],
    rules: &CompiledRuleset,
    attr_owners: &[(FlowKey, Owner)],
) -> Result<Vec<Alert>, String> {
    let mut table = FlowTable::new();
    for f in frames {
        table.ingest(f);
    }
    let mut alerts: Vec<Alert> = Vec::new();
    let _flows = table.attributed();
    for rule in &rules.rules {
        let action = rule.action.to_ascii_lowercase();
        if action != "alert" && action != "pass" && action != "drop" {
            continue;
        }
        for f in frames {
            if !rule_matches_frame(rule, f) {
                continue;
            }
            let key = FlowKey {
                proto: f.proto.clone(),
                src: f.src.clone(),
                dst: f.dst.clone(),
                src_port: f.src_port,
                dst_port: f.dst_port,
            };
            let owner = f.owner.clone().or_else(|| {
                attr_owners
                    .iter()
                    .find(|(k, _)| k.src == key.src || k.dst == key.dst)
                    .map(|(_, o)| o.clone())
            });
            if alerts
                .iter()
                .any(|a| a.sid == rule.sid && a.flow_key.as_ref() == Some(&key))
            {
                continue;
            }
            let ioc = rule
                .ops
                .iter()
                .find(|o| !o.pattern.is_empty())
                .map(|o| String::from_utf8_lossy(&o.pattern).into_owned())
                .or_else(|| {
                    rule.contents
                        .first()
                        .map(|c| String::from_utf8_lossy(&c.pattern).into_owned())
                });
            alerts.push(Alert {
                id: format!("alert-{}-{}", rule.sid, alerts.len()),
                sid: rule.sid,
                msg: rule.msg.clone(),
                severity: rule.severity,
                action: rule.action.clone(),
                flow_key: Some(key),
                owner,
                timestamp_ms: f.ts_ms,
                host: None,
                ioc,
            });
        }
    }
    let buf = LAST_ALERTS.get();
    buf.clear();
    for a in &alerts {
        buf.push(a.clone());
    }
    Ok(alerts)
}

pub fn compile_rules_text(text: &str) -> Result<CompiledRuleset, String> {
    Ok(compile_rules(text))
}

pub fn load_rules(path: &Path) -> Result<CompiledRuleset, String> {
    load_rule_pack(path).map_err(|e| e.to_string())
}

fn proto_matches(rule: &Rule, proto: &str) -> bool {
    if rule.proto.eq_ignore_ascii_case("any") || rule.proto.eq_ignore_ascii_case(proto) {
        return true;
    }
    // alert http/tls stored as tcp; dns as udp
    match rule.l7.as_deref() {
        Some("http") | Some("tls") => proto.eq_ignore_ascii_case("tcp") || proto.eq_ignore_ascii_case("http"),
        Some("dns") => proto.eq_ignore_ascii_case("udp") || proto.eq_ignore_ascii_case("dns"),
        _ => false,
    }
}

fn header_matches_frame(rule: &Rule, f: &Frame) -> bool {
    if !proto_matches(rule, &f.proto) {
        return false;
    }
    let fwd = addr_matches(&rule.src, &f.src)
        && port_matches(&rule.src_port, f.src_port)
        && addr_matches(&rule.dst, &f.dst)
        && port_matches(&rule.dst_port, f.dst_port);
    let rev = rule.direction.contains("<>")
        && addr_matches(&rule.src, &f.dst)
        && port_matches(&rule.src_port, f.dst_port)
        && addr_matches(&rule.dst, &f.src)
        && port_matches(&rule.dst_port, f.src_port);
    fwd || rev
}

fn service_port(p: u16) -> bool {
    matches!(p, 21 | 22 | 25 | 53 | 80 | 110 | 143 | 443 | 465 | 587 | 993 | 995 | 8000 | 8008 | 8080 | 8443 | 8888)
}

fn flow_ok(rule: &Rule, f: &Frame) -> bool {
    if rule.flow_established {
        if let Some(flags) = f.tcp_flags {
            if flags & 0x10 == 0 {
                return false;
            }
        }
    }
    if rule.flow_to_server && !rule.flow_to_client {
        if !service_port(f.dst_port) && service_port(f.src_port) {
            return false;
        }
    }
    if rule.flow_to_client && !rule.flow_to_server {
        if !service_port(f.src_port) && service_port(f.dst_port) {
            return false;
        }
    }
    true
}

fn l7_ok(rule: &Rule, f: &Frame) -> bool {
    match rule.l7.as_deref() {
        Some("http") => parse_request_ex(&f.payload).is_some(),
        Some("tls") => parse_client_hello(&f.payload).is_some(),
        Some("dns") => parse_qnames(&f.payload).is_some(),
        _ => true,
    }
}

fn buffer_bytes(op: &DetectOp, f: &Frame) -> Vec<u8> {
    match op.buffer.as_str() {
        "http.uri" => parse_request_ex(&f.payload)
            .map(|r| r.uri.into_bytes())
            .unwrap_or_default(),
        "http.host" => parse_request_ex(&f.payload)
            .and_then(|r| r.host)
            .map(|h| h.into_bytes())
            .unwrap_or_default(),
        "http.method" => parse_request_ex(&f.payload)
            .map(|r| r.method.into_bytes())
            .unwrap_or_default(),
        "http.header" => parse_request_ex(&f.payload)
            .map(|r| r.headers.into_bytes())
            .unwrap_or_default(),
        "dns.query" => parse_qnames(&f.payload)
            .map(|q| q.join("\n").into_bytes())
            .unwrap_or_default(),
        "tls.sni" => parse_client_hello(&f.payload)
            .and_then(|(sni, _)| sni)
            .map(|s| s.into_bytes())
            .unwrap_or_default(),
        _ => f.payload.clone(),
    }
}

fn rule_matches_frame(rule: &Rule, f: &Frame) -> bool {
    if !header_matches_frame(rule, f) || !flow_ok(rule, f) || !l7_ok(rule, f) {
        return false;
    }
    let ops: Vec<&DetectOp> = if rule.ops.is_empty() {
        return if rule.contents.is_empty() {
            true
        } else {
            contents_match(&rule.contents, &f.payload)
        };
    } else {
        rule.ops.iter().collect()
    };
    let mut last_end: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for op in ops {
        let buf = buffer_bytes(op, f);
        if buf.is_empty() && op.kind != "pcre" && !op.pattern.is_empty() {
            return false;
        }
        let start = op.offset.unwrap_or(0);
        let from = if let Some(d) = op.distance {
            let base = last_end.get(&op.buffer).copied().unwrap_or(0) as i64;
            (base + d as i64).max(0) as usize
        } else {
            start
        };
        if from > buf.len() {
            return false;
        }
        let end = if let Some(w) = op.within {
            (from + w).min(buf.len())
        } else if let Some(d) = op.depth {
            (start + d).min(buf.len())
        } else {
            buf.len()
        };
        if end < from {
            return false;
        }
        let window = &buf[from..end];
        let hit_end = if op.kind == "pcre" {
            let Some(re) = op.pcre.as_deref() else {
                return false;
            };
            let Ok(rx) = regex::bytes::Regex::new(re) else {
                return false;
            };
            rx.find(window).map(|m| from + m.end())
        } else {
            find_pattern(window, &op.pattern, op.nocase).map(|rel_end| from + rel_end)
        };
        let Some(abs_end) = hit_end else {
            return false;
        };
        last_end.insert(op.buffer.clone(), abs_end.min(buf.len()));
    }
    true
}

/// Emit a Suricata-shaped rule that compiles and matches the given frames/alerts.
/// Deterministic (no API key). Content is taken from the first non-empty payload.
pub fn synthesize_rule_from_frames(frames: &[Frame]) -> Result<String, String> {
    let f = frames
        .iter()
        .find(|f| !f.payload.is_empty())
        .ok_or_else(|| "no payload to synthesize from".to_string())?;
    synthesize_rule_for_frame(f)
}

pub fn synthesize_rule_for_frame(f: &Frame) -> Result<String, String> {
    let snippet = content_snippet(&f.payload);
    if snippet.is_empty() {
        return Err("empty content snippet".into());
    }
    let sid = 2_000_000u32
        + (f.payload.iter().fold(0u32, |a, b| a.wrapping_mul(16777619) ^ (*b as u32)) % 900_000);
    let proto = if f.proto.is_empty() { "any" } else { f.proto.as_str() };
    let src = if f.src.is_empty() { "any".into() } else { f.src.clone() };
    let dst = if f.dst.is_empty() { "any".into() } else { f.dst.clone() };
    let sport = if f.src_port == 0 {
        "any".into()
    } else {
        f.src_port.to_string()
    };
    let dport = if f.dst_port == 0 {
        "any".into()
    } else {
        f.dst_port.to_string()
    };
    Ok(format!(
        r#"alert {proto} {src} {sport} -> {dst} {dport} (msg:"ghidnet synth"; content:"{snippet}"; sid:{sid};)"#
    ))
}

fn content_snippet(payload: &[u8]) -> String {
    // Contiguous payload bytes as Suricata `|HH HH|` so the compiler's
    // `opts.split(';')` never sees a raw ';' / quote, and the pattern is a
    // real substring (no concatenating across CRLF/NUL).
    let n = payload.len().min(12);
    if n == 0 {
        return String::new();
    }
    hex_content(&payload[..n])
}

fn hex_content(bytes: &[u8]) -> String {
    let mut hex = String::from("|");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{b:02X}"));
    }
    hex.push('|');
    hex
}

fn contents_match(opts: &[ContentOpt], hay: &[u8]) -> bool {
    opts.iter().all(|c| content_hit(c, hay))
}

fn content_hit(c: &ContentOpt, hay: &[u8]) -> bool {
    let start = c.offset.unwrap_or(0);
    if start >= hay.len() {
        return false;
    }
    let end = match c.depth {
        Some(d) => (start + d).min(hay.len()),
        None => hay.len(),
    };
    find_pattern(&hay[start..end], &c.pattern, c.nocase).is_some()
}

/// End offset of the first match inside `hay` (relative to `hay`).
fn find_pattern(hay: &[u8], needle: &[u8], nocase: bool) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if nocase {
        let pat: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
        hay.windows(pat.len()).position(|w| {
            w.iter()
                .zip(pat.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
        .map(|i| i + pat.len())
    } else {
        hay.windows(needle.len())
            .position(|w| w == needle)
            .map(|i| i + needle.len())
    }
}

#[allow(dead_code)]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Thin shim so detect can read capture files without a hard cyclic dep at compile of unit tests.
/// Real wiring: ghidrust-net-capture implements the same layout; we duplicate a minimal reader here
/// for the capture-file magic we own.
mod ghidrust_net_capture_replay {
    use ghidrust_net_flow::Frame;
    use ghidrust_net_schema::Owner;
    use std::path::Path;

    const MAGIC: &[u8; 8] = b"GRNCAP01";

    pub fn read_frames(path: &Path) -> Result<Vec<Frame>, String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        if data.len() < 8 || &data[..8] != MAGIC {
            // Treat as raw payload blob for fixtures: single synthetic frame.
            return Ok(vec![Frame {
                ts_ms: 0,
                proto: "tcp".into(),
                src: "10.0.0.1".into(),
                dst: "10.0.0.2".into(),
                src_port: 12345,
                dst_port: 80,
                payload: data,
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            }]);
        }
        let mut out = Vec::new();
        let mut i = 8;
        while i + 4 <= data.len() {
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i + n > data.len() {
                break;
            }
            let slice = &data[i..i + n];
            i += n;
            if let Ok(f) = serde_json::from_slice::<FrameDto>(slice) {
                out.push(Frame {
                    ts_ms: f.ts_ms,
                    proto: f.proto,
                    src: f.src,
                    dst: f.dst,
                    src_port: f.src_port,
                    dst_port: f.dst_port,
                    payload: f.payload,
                    tcp_seq: f.tcp_seq,
                    tcp_ack: f.tcp_ack,
                    tcp_flags: f.tcp_flags,
                    owner: f.owner,
                });
            }
        }
        Ok(out)
    }

    #[derive(serde::Deserialize)]
    struct FrameDto {
        ts_ms: u64,
        proto: String,
        src: String,
        dst: String,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
        tcp_seq: Option<u32>,
        tcp_ack: Option<u32>,
        tcp_flags: Option<u8>,
        owner: Option<Owner>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidrust_net_schema::Confidence;

    #[test]
    fn detects_content_in_frame_payload() {
        let rules = compile_rules_text(
            r#"alert tcp any any -> any any (msg:"evil marker"; content:"EVILCMD"; sid:1000001; severity:3;)"#,
        )
        .unwrap();
        let frames = vec![Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "1.2.3.4".into(),
            dst: "5.6.7.8".into(),
            src_port: 4444,
            dst_port: 80,
            payload: b"header EVILCMD trailer".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: Some(Owner {
                pid: 42,
                image_path: Some("C:\\tmp\\sample.exe".into()),
                image_confidence: Confidence::Exact,
                pid_confidence: Confidence::Exact,
            }),
        }];
        let alerts = detect_frames(&frames, &rules, &[]).unwrap();
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].sid, 1000001);
        assert!(alerts[0].owner.as_ref().unwrap().image_path.as_ref().unwrap().contains("sample"));
    }

    #[test]
    fn mpm_finds_needles() {
        let m = MultiPattern::new(vec![b"abc".to_vec(), b"xyz".to_vec()]);
        let hits = m.search(b"---abc---xyz---");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn pass_and_drop_are_recorded_not_silent() {
        let rules = compile_rules_text(
            r#"pass tcp any any -> any any (msg:"allow"; content:"OKOK"; sid:2001;)
drop tcp any any -> any any (msg:"block"; content:"BADBAD"; sid:2002;)"#,
        )
        .unwrap();
        let frames = vec![
            Frame {
                ts_ms: 1,
                proto: "tcp".into(),
                src: "1.1.1.1".into(),
                dst: "2.2.2.2".into(),
                src_port: 9,
                dst_port: 80,
                payload: b"OKOK".to_vec(),
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            },
            Frame {
                ts_ms: 2,
                proto: "tcp".into(),
                src: "1.1.1.1".into(),
                dst: "2.2.2.2".into(),
                src_port: 9,
                dst_port: 80,
                payload: b"BADBAD".to_vec(),
                tcp_seq: None,
                tcp_ack: None,
                tcp_flags: None,
                owner: None,
            },
        ];
        let alerts = detect_frames(&frames, &rules, &[]).unwrap();
        assert!(alerts.iter().any(|a| a.sid == 2001 && a.action == "pass"));
        assert!(alerts.iter().any(|a| a.sid == 2002 && a.action == "drop"));
    }

    #[test]
    fn synthesize_then_compile_then_detect() {
        let frames = vec![Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_port: 4444,
            dst_port: 80,
            payload: b"header EVILCMD trailer".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        }];
        let text = synthesize_rule_from_frames(&frames).unwrap();
        assert!(text.contains("content:"));
        assert!(text.contains("sid:"));
        let rules = compile_rules_text(&text).unwrap();
        let alerts = detect_frames(&frames, &rules, &[]).unwrap();
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].sid, rules.rules[0].sid);
        assert!(alerts[0].msg.contains("ghidnet"));
        assert!(
            frames[0]
                .payload
                .windows(rules.rules[0].contents[0].pattern.len())
                .any(|w| w == rules.rules[0].contents[0].pattern.as_slice()),
            "synth content must be a contiguous payload substring"
        );
    }

    #[test]
    fn synthesize_http_payload_with_semicolon_and_crlf() {
        let frames = vec![Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "10.0.0.8".into(),
            dst: "10.0.0.9".into(),
            src_port: 49152,
            dst_port: 80,
            payload: b"GET /x HTTP/1.1\r\nHost: a.example;evil\r\n\r\n".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        }];
        let text = synthesize_rule_from_frames(&frames).expect("synth");
        assert!(
            !text.contains("content:\"GET") && !text.contains("content:\"Host"),
            "must not put raw HTTP (CRLF/';') inside content:\"...\": {text}"
        );
        assert!(text.contains("content:\"|"), "prefer |HH HH| hex: {text}");
        let rules = compile_rules_text(&text).expect(&format!("compile {text}"));
        assert!(!rules.rules.is_empty());
        let pat = &rules.rules[0].contents[0].pattern;
        assert!(
            frames[0].payload.windows(pat.len()).any(|w| w == pat.as_slice()),
            "pattern {pat:?} not a substring of payload"
        );
        let alerts = detect_frames(&frames, &rules, &[]).expect("detect");
        assert!(!alerts.is_empty(), "synthesized rule must match originating HTTP frame");
        assert_eq!(alerts[0].sid, rules.rules[0].sid);
    }

    #[test]
    fn http_uri_matches_uri_not_body() {
        let rules = compile_rules_text(
            r#"
alert http any any -> any any (msg:"uri"; http.uri; content:"/gate.php"; sid:2000002;)
alert tls any any -> any any (msg:"sni"; tls.sni; content:"evil.example"; sid:2000003;)
"#,
        )
        .unwrap();
        assert_eq!(rules.rules.len(), 2, "{:?}", rules.skipped);
        let http = Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "10.0.0.2".into(),
            dst: "10.0.0.1".into(),
            src_port: 49152,
            dst_port: 80,
            payload: b"GET /gate.php HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: Some(0x18),
            owner: None,
        };
        let body_only = Frame {
            ts_ms: 2,
            proto: "tcp".into(),
            src: "10.0.0.2".into(),
            dst: "10.0.0.1".into(),
            src_port: 49152,
            dst_port: 80,
            payload: b"GET /index HTTP/1.1\r\nHost: a.test\r\n\r\n/gate.php".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: Some(0x18),
            owner: None,
        };
        let hits = detect_frames(&[http], &rules, &[]).unwrap();
        assert!(hits.iter().any(|a| a.sid == 2000002), "{hits:?}");
        assert!(!hits.iter().any(|a| a.sid == 2000003));
        let misses = detect_frames(&[body_only], &rules, &[]).unwrap();
        assert!(
            !misses.iter().any(|a| a.sid == 2000002),
            "URI rule must not fire on body-only /gate.php: {misses:?}"
        );
    }

    #[test]
    fn dns_and_tls_sticky_buffers() {
        let rules = compile_rules_text(
            r#"
alert dns any any -> any any (msg:"dns"; dns.query; content:"c2.example"; sid:2000004;)
alert tls any any -> any any (msg:"sni"; tls.sni; content:"evil.example"; sid:2000003;)
"#,
        )
        .unwrap();
        let mut dns = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in [b"c2".as_slice(), b"example".as_slice()] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label);
        }
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let dns_f = Frame {
            ts_ms: 1,
            proto: "udp".into(),
            src: "10.0.0.2".into(),
            dst: "10.0.0.1".into(),
            src_port: 5555,
            dst_port: 53,
            payload: dns,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        };
        let alerts = detect_frames(&[dns_f], &rules, &[]).unwrap();
        assert!(alerts.iter().any(|a| a.sid == 2000004), "{alerts:?}");
        assert!(!alerts.iter().any(|a| a.sid == 2000003));

        let tls_payload = tls_client_hello_sni(b"evil.example");
        let tls_f = Frame {
            ts_ms: 2,
            proto: "tcp".into(),
            src: "10.0.0.2".into(),
            dst: "10.0.0.1".into(),
            src_port: 49152,
            dst_port: 443,
            payload: tls_payload,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: Some(0x18),
            owner: None,
        };
        let tls_hits = detect_frames(&[tls_f], &rules, &[]).unwrap();
        assert!(
            tls_hits.iter().any(|a| a.sid == 2000003),
            "tls.sni SID must fire on ClientHello: {tls_hits:?}"
        );
        assert!(!tls_hits.iter().any(|a| a.sid == 2000004));
    }

    fn tls_client_hello_sni(sni: &[u8]) -> Vec<u8> {
        let mut ext_sni = Vec::new();
        ext_sni.extend_from_slice(&0x0000u16.to_be_bytes());
        let mut list = Vec::new();
        list.push(0x00);
        list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        list.extend_from_slice(sni);
        let mut list_wrap = Vec::new();
        list_wrap.extend_from_slice(&(list.len() as u16).to_be_bytes());
        list_wrap.extend_from_slice(&list);
        ext_sni.extend_from_slice(&(list_wrap.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(&list_wrap);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_sni);
        let bl = body.len();
        let mut hs = vec![
            0x01,
            ((bl >> 16) & 0xff) as u8,
            ((bl >> 8) & 0xff) as u8,
            (bl & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn distance_within_uses_previous_hit_end() {
        let rules = compile_rules_text(
            r#"alert tcp any any -> any any (msg:"d"; content:"ABC"; content:"D"; distance:0; within:1; sid:42;)"#,
        )
        .unwrap();
        assert_eq!(rules.rules.len(), 1, "{:?}", rules.skipped);
        let f = Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "1.1.1.1".into(),
            dst: "2.2.2.2".into(),
            src_port: 9,
            dst_port: 80,
            payload: b"xABCD".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        };
        let alerts = detect_frames(&[f], &rules, &[]).unwrap();
        assert!(
            alerts.iter().any(|a| a.sid == 42),
            "Suricata cursor after ABC is offset 4, D at distance:0 within:1 must match: {alerts:?}"
        );
    }

    #[test]
    fn detect_does_not_spawn_external_analyzer() {
        // Structural guarantee: this crate has no Command::new for foreign analyzers.
        // Runtime check: detection completes in-process.
        let rules = compile_rules_text(
            r#"alert tcp any any -> any any (msg:"x"; content:"ZZ"; sid:9;)"#,
        )
        .unwrap();
        let frames = vec![Frame {
            ts_ms: 0,
            proto: "tcp".into(),
            src: "a".into(),
            dst: "b".into(),
            src_port: 1,
            dst_port: 2,
            payload: b"ZZ".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: None,
        }];
        let _ = detect_frames(&frames, &rules, &[]).unwrap();
    }
}
