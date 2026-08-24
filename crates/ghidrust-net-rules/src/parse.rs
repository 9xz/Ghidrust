//! Suricata/ET-shaped rule parse — fail-closed per SID.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    pub proto: String,
    pub src: String,
    pub src_port: String,
    pub direction: String,
    pub dst: String,
    pub dst_port: String,
    pub sid: u32,
    pub msg: String,
    pub severity: u8,
    pub contents: Vec<ContentOpt>,
    #[serde(default)]
    pub skipped_options: Vec<String>,
    #[serde(default)]
    pub ops: Vec<DetectOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l7: Option<String>,
    #[serde(default)]
    pub flow_established: bool,
    #[serde(default)]
    pub flow_to_server: bool,
    #[serde(default)]
    pub flow_to_client: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentOpt {
    pub pattern: Vec<u8>,
    pub nocase: bool,
    pub offset: Option<usize>,
    pub depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectOp {
    /// payload | http.uri | http.host | http.method | http.header | dns.query | tls.sni
    pub buffer: String,
    /// content | pcre
    pub kind: String,
    #[serde(default)]
    pub pattern: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcre: Option<String>,
    #[serde(default)]
    pub nocase: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distance: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSid {
    pub sid: u32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompiledRuleset {
    pub rules: Vec<Rule>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub skipped: Vec<SkippedSid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for RuleError {}

pub type Vars = BTreeMap<String, String>;

pub fn default_vars() -> Vars {
    let mut v = Vars::new();
    let home = "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8]";
    v.insert("HOME_NET".into(), home.into());
    v.insert("EXTERNAL_NET".into(), "any".into());
    v.insert("HTTP_PORTS".into(), "[80,443,8080,8000,8008,8888]".into());
    v.insert("SMTP_PORTS".into(), "[25,587,465]".into());
    v.insert("FTP_PORTS".into(), "21".into());
    v.insert("SSH_PORTS".into(), "22".into());
    v.insert("ORACLE_PORTS".into(), "1521".into());
    v.insert("DNS_PORTS".into(), "53".into());
    v.insert("SIP_PORTS".into(), "[5060,5061]".into());
    v.insert("FILE_DATA_PORTS".into(), "[80,443,8080]".into());
    v.insert("SHELLCODE_PORTS".into(), "!80".into());
    apply_suricata_aliases(&mut v);
    v
}

/// Suricata.yaml defaults: HTTP_SERVERS/SQL_SERVERS/… alias HOME_NET unless set.
pub fn apply_suricata_aliases(v: &mut Vars) {
    let home = v
        .get("HOME_NET")
        .cloned()
        .unwrap_or_else(|| "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8]".into());
    let ext = v
        .get("EXTERNAL_NET")
        .cloned()
        .unwrap_or_else(|| "any".into());
    for k in [
        "HTTP_SERVERS",
        "SMTP_SERVERS",
        "SQL_SERVERS",
        "DNS_SERVERS",
        "TELNET_SERVERS",
        "DNP3_SERVER",
        "DNP3_CLIENT",
        "MODBUS_CLIENT",
        "MODBUS_SERVER",
        "ENIP_CLIENT",
        "ENIP_SERVER",
    ] {
        v.entry(k.into()).or_insert_with(|| home.clone());
    }
    v.entry("AIM_SERVERS".into()).or_insert_with(|| ext.clone());
    // Resolve `$HOME_NET` / `$EXTERNAL_NET` copies from a vars file.
    let keys: Vec<String> = v.keys().cloned().collect();
    for k in keys {
        if let Some(val) = v.get(&k).cloned() {
            if let Some(name) = val.trim().strip_prefix('$') {
                if let Some(inner) = v.get(name).cloned() {
                    v.insert(k, inner);
                }
            }
        }
    }
}

pub fn load_vars_file(path: &Path) -> Vars {
    let mut v = default_vars();
    let Ok(text) = std::fs::read_to_string(path) else {
        return v;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, val)) = line.split_once(':') {
            let k = k.trim().trim_start_matches('$');
            v.insert(k.to_string(), val.trim().to_string());
        } else if let Some((k, val)) = line.split_once('=') {
            let k = k.trim().trim_start_matches('$');
            v.insert(k.to_string(), val.trim().to_string());
        }
    }
    apply_suricata_aliases(&mut v);
    v
}

pub fn load_rule_pack(path: &Path) -> Result<CompiledRuleset, RuleError> {
    let text = std::fs::read_to_string(path).map_err(|e| RuleError {
        code: "io".into(),
        message: e.to_string(),
    })?;
    Ok(compile_rules(&text))
}

pub fn compile_rules(text: &str) -> CompiledRuleset {
    compile_rules_with(text, &default_vars())
}

pub fn compile_rules_with(text: &str, vars: &Vars) -> CompiledRuleset {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("alert ip any any -> any any (msg:\"GPL") {
            // keep GPL lines; they parse
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_rule_line(line, vars) {
            Ok(ParseOut::Rule(r)) => {
                for s in &r.skipped_options {
                    warnings.push(format!("sid {}: skipped option '{s}'", r.sid));
                }
                rules.push(r);
            }
            Ok(ParseOut::Skip { sid, reason, msg }) => {
                skipped.push(SkippedSid { sid, reason, msg });
            }
            Err(e) => {
                skipped.push(SkippedSid {
                    sid: 0,
                    reason: format!("line {}: {}", lineno + 1, e.message),
                    msg: None,
                });
            }
        }
    }
    CompiledRuleset {
        rules,
        warnings,
        skipped,
    }
}

enum ParseOut {
    Rule(Rule),
    Skip {
        sid: u32,
        reason: String,
        msg: Option<String>,
    },
}

fn parse_rule_line(line: &str, vars: &Vars) -> Result<ParseOut, RuleError> {
    let (header, opts) = if let Some(i) = line.find('(') {
        let end = line.rfind(')').ok_or_else(|| RuleError {
            code: "parse".into(),
            message: "missing closing ')'".into(),
        })?;
        (&line[..i], &line[i + 1..end])
    } else {
        return Err(RuleError {
            code: "parse".into(),
            message: "missing options block".into(),
        });
    };
    let parts: Vec<_> = header.split_whitespace().collect();
    if parts.len() < 7 {
        return Err(RuleError {
            code: "parse".into(),
            message: "expected: action proto src sport dir dst dport".into(),
        });
    }
    let mut src = expand_token(parts[2], vars)?;
    let mut src_port = expand_token(parts[3], vars)?;
    let mut dst = expand_token(parts[5], vars)?;
    let mut dst_port = expand_token(parts[6], vars)?;
    let proto_raw = parts[1];
    let l7 = match proto_raw.to_ascii_lowercase().as_str() {
        "http" => Some("http".into()),
        "dns" => Some("dns".into()),
        "tls" | "ssl" => Some("tls".into()),
        _ => None,
    };
    let proto = match proto_raw.to_ascii_lowercase().as_str() {
        "http" | "tls" | "ssl" => "tcp".into(),
        "dns" => "udp".into(),
        other => other.to_string(),
    };

    let mut sid = 0u32;
    let mut msg = String::new();
    let mut severity = 2u8;
    let mut contents = Vec::new();
    let mut skipped_opts = Vec::new();
    let mut ops: Vec<DetectOp> = Vec::new();
    let mut buffer = "payload".to_string();
    let mut skip_reason: Option<String> = None;
    let mut flow_established = false;
    let mut flow_to_server = false;
    let mut flow_to_client = false;

    for opt in split_options(opts) {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        let lower = opt.to_ascii_lowercase();
        if lower.starts_with("msg:") {
            msg = unquote(opt[4..].trim());
        } else if lower.starts_with("sid:") {
            sid = opt[4..].trim().parse().unwrap_or(0);
        } else if lower.starts_with("severity:") || lower.starts_with("priority:") {
            severity = opt.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(2);
        } else if is_sticky(&lower) {
            buffer = sticky_name(&lower);
        } else if lower.starts_with("content:") {
            let (pat, flags) = split_content(opt[8..].trim());
            let mut op = DetectOp {
                buffer: buffer.clone(),
                kind: "content".into(),
                pattern: unescape_content(&unquote(&pat)),
                pcre: None,
                nocase: false,
                offset: None,
                depth: None,
                distance: None,
                within: None,
            };
            for f in flags {
                apply_flag(&mut op, f);
            }
            if op.buffer == "payload" {
                contents.push(ContentOpt {
                    pattern: op.pattern.clone(),
                    nocase: op.nocase,
                    offset: op.offset,
                    depth: op.depth,
                });
            }
            ops.push(op);
        } else if lower.starts_with("pcre:") {
            let raw = unquote(opt[5..].trim());
            match rust_pcre(&raw) {
                Ok((re, nocase)) => {
                    ops.push(DetectOp {
                        buffer: buffer.clone(),
                        kind: "pcre".into(),
                        pattern: Vec::new(),
                        pcre: Some(re),
                        nocase,
                        ..Default::default()
                    });
                }
                Err(e) => skip_reason = Some(format!("invalid pcre: {e}")),
            }
        } else if lower == "nocase" {
            if let Some(c) = ops.last_mut() {
                c.nocase = true;
            }
            if let Some(c) = contents.last_mut() {
                c.nocase = true;
            }
        } else if lower.starts_with("offset:") {
            let v = opt[7..].trim().parse().ok();
            if let Some(c) = ops.last_mut() {
                c.offset = v;
            }
            if let Some(c) = contents.last_mut() {
                c.offset = v;
            }
        } else if lower.starts_with("depth:") {
            let v = opt[6..].trim().parse().ok();
            if let Some(c) = ops.last_mut() {
                c.depth = v;
            }
            if let Some(c) = contents.last_mut() {
                c.depth = v;
            }
        } else if lower.starts_with("distance:") {
            if let Some(c) = ops.last_mut() {
                c.distance = opt[9..].trim().parse().ok();
            }
        } else if lower.starts_with("within:") {
            if let Some(c) = ops.last_mut() {
                c.within = opt[7..].trim().parse().ok();
            }
        } else if lower.starts_with("flow:") {
            for p in opt[5..].split(',') {
                match p.trim() {
                    "established" => flow_established = true,
                    "to_server" | "from_client" => flow_to_server = true,
                    "to_client" | "from_server" => flow_to_client = true,
                    "stateless" | "no_stream" | "only_stream" => {}
                    other => skipped_opts.push(format!("flow:{other}")),
                }
            }
        } else if lower.starts_with("flowbits:")
            || lower.starts_with("xbits:")
            || lower.starts_with("flowint:")
        {
            skip_reason = Some("flowbits".into());
        } else if lower.starts_with("file-data")
            || lower.starts_with("file.data")
            || lower.starts_with("filemagic")
            || lower.starts_with("file.md5")
        {
            skip_reason = Some("file-data".into());
        } else if lower.starts_with("ja3") || lower.starts_with("ja3s") || lower == "ja3.hash" {
            skip_reason = Some("ja3".into());
        } else if lower.starts_with("lua:") || lower.starts_with("luajit:") {
            skip_reason = Some("lua".into());
        } else if lower.starts_with("threshold:")
            || lower.starts_with("detection_filter:")
            || lower.starts_with("limit:")
        {
            skip_reason = Some("threshold".into());
        } else if lower.starts_with("classtype:")
            || lower.starts_with("rev:")
            || lower.starts_with("reference:")
            || lower.starts_with("metadata:")
            || lower.starts_with("tag:")
            || lower.starts_with("priority:")
            || lower == "fast_pattern"
            || lower.starts_with("fast_pattern:")
            || lower.starts_with("target:")
            || lower.starts_with("gid:")
        {
            // recorded no-ops
        } else if lower.starts_with("http.")
            || lower.starts_with("dns.")
            || lower.starts_with("tls.")
            || lower.starts_with("ssl_")
        {
            skip_reason = Some(format!("buffer {opt}"));
        } else if lower.starts_with("byte_test")
            || lower.starts_with("byte_jump")
            || lower.starts_with("byte_extract")
            || lower.starts_with("isdataat")
            || lower.starts_with("dsize")
            || lower.starts_with("stream_size")
            || lower.starts_with("itype")
            || lower.starts_with("icode")
            || lower.starts_with("icmp_")
            || lower.starts_with("flags:")
            || lower.starts_with("window:")
            || lower.starts_with("seq:")
            || lower.starts_with("ack:")
            || lower.starts_with("id:")
            || lower.starts_with("geoip")
            || lower.starts_with("xbits")
            || lower.starts_with("app-layer")
            || lower.starts_with("urilen")
            || lower.starts_with("bsize")
        {
            skip_reason = Some(format!("keyword {opt}"));
        } else {
            skipped_opts.push(opt.to_string());
        }
    }

    if sid == 0 {
        return Err(RuleError {
            code: "parse".into(),
            message: "sid required".into(),
        });
    }
    if let Some(reason) = skip_reason {
        return Ok(ParseOut::Skip {
            sid,
            reason,
            msg: if msg.is_empty() { None } else { Some(msg) },
        });
    }
    // Unknown leftover options that look like matchers → skip (don't half-match).
    for s in &skipped_opts {
        let sl = s.to_ascii_lowercase();
        if sl.contains(':') && !sl.starts_with("classtype") {
            return Ok(ParseOut::Skip {
                sid,
                reason: format!("unknown option {s}"),
                msg: if msg.is_empty() { None } else { Some(msg) },
            });
        }
    }

    let _ = (&mut src, &mut src_port, &mut dst, &mut dst_port);
    Ok(ParseOut::Rule(Rule {
        action: parts[0].into(),
        proto,
        src,
        src_port,
        direction: parts[4].into(),
        dst,
        dst_port,
        sid,
        msg,
        severity,
        contents,
        skipped_options: skipped_opts,
        ops,
        l7,
        flow_established,
        flow_to_server,
        flow_to_client,
    }))
}

fn expand_token(tok: &str, vars: &Vars) -> Result<String, RuleError> {
    if let Some(name) = tok.strip_prefix('$') {
        let name = name.trim();
        vars.get(name).cloned().ok_or_else(|| RuleError {
            code: "var".into(),
            message: format!("undefined var ${name}"),
        })
    } else if let Some(rest) = tok.strip_prefix("!$") {
        let name = rest.trim();
        let inner = vars.get(name).ok_or_else(|| RuleError {
            code: "var".into(),
            message: format!("undefined var ${name}"),
        })?;
        Ok(format!("!{inner}"))
    } else {
        Ok(tok.to_string())
    }
}

fn is_sticky(lower: &str) -> bool {
    matches!(
        lower.trim_end_matches(':'),
        "http.uri"
            | "http_uri"
            | "http.uri.raw"
            | "http.host"
            | "http_host"
            | "http.method"
            | "http_method"
            | "http.header"
            | "http_header"
            | "http.header.raw"
            | "dns.query"
            | "dns_query"
            | "dns.rrname"
            | "tls.sni"
            | "tls_sni"
            | "tls.sni.raw"
    )
}

fn sticky_name(lower: &str) -> String {
    match lower.trim_end_matches(':') {
        "http.uri" | "http_uri" | "http.uri.raw" => "http.uri",
        "http.host" | "http_host" => "http.host",
        "http.method" | "http_method" => "http.method",
        "http.header" | "http_header" | "http.header.raw" => "http.header",
        "dns.query" | "dns_query" | "dns.rrname" => "dns.query",
        "tls.sni" | "tls_sni" | "tls.sni.raw" => "tls.sni",
        other => other,
    }
    .into()
}

fn apply_flag(op: &mut DetectOp, f: &str) {
    match f {
        "nocase" => op.nocase = true,
        other if other.starts_with("offset:") => {
            op.offset = other["offset:".len()..].parse().ok();
        }
        other if other.starts_with("depth:") => {
            op.depth = other["depth:".len()..].parse().ok();
        }
        other if other.starts_with("distance:") => {
            op.distance = other["distance:".len()..].parse().ok();
        }
        other if other.starts_with("within:") => {
            op.within = other["within:".len()..].parse().ok();
        }
        _ => {}
    }
}

fn split_options(opts: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut esc = false;
    for c in opts.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        if c == '\\' && in_dq {
            cur.push(c);
            esc = true;
            continue;
        }
        if c == '"' {
            in_dq = !in_dq;
            cur.push(c);
            continue;
        }
        if c == ';' && !in_dq {
            let t = cur.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
            cur.clear();
            continue;
        }
        cur.push(c);
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn split_content(s: &str) -> (String, Vec<&str>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            let pat = format!("\"{}\"", &rest[..end]);
            let after = rest[end + 1..].trim().trim_start_matches(',').trim();
            let flags: Vec<_> = if after.is_empty() {
                Vec::new()
            } else {
                after.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect()
            };
            return (pat, flags);
        }
    }
    (s.to_string(), Vec::new())
}

fn unescape_content(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '|' {
            let mut hex = String::new();
            while let Some(&n) = chars.peek() {
                if n == '|' {
                    chars.next();
                    break;
                }
                hex.push(n);
                chars.next();
            }
            for part in hex.split_whitespace() {
                if let Ok(b) = u8::from_str_radix(part, 16) {
                    out.push(b);
                }
            }
        } else {
            out.push(c as u8);
        }
    }
    out
}

/// Convert Suricata `pcre:"/pat/flags"` to a Rust regex string.
fn rust_pcre(raw: &str) -> Result<(String, bool), String> {
    let s = raw.trim();
    let body = if let Some(rest) = s.strip_prefix('/') {
        if let Some(end) = rest.rfind('/') {
            let pat = &rest[..end];
            let flags = &rest[end + 1..];
            let mut pfx = String::new();
            let mut nocase = false;
            if flags.contains('i') {
                pfx.push_str("(?i)");
                nocase = true;
            }
            if flags.contains('s') {
                pfx.push_str("(?s)");
            }
            if flags.contains('m') {
                pfx.push_str("(?m)");
            }
            (format!("{pfx}{pat}"), nocase)
        } else {
            (s.to_string(), false)
        }
    } else {
        (s.to_string(), false)
    };
    regex::Regex::new(&body.0).map_err(|e| e.to_string())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_content_rule() {
        let text = r#"alert tcp any any -> any any (msg:"probe"; content:"EVIL"; nocase; sid:1000001; severity:2;)"#;
        let set = compile_rules(text);
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].sid, 1000001);
        assert_eq!(set.rules[0].contents[0].pattern, b"EVIL");
        assert!(set.rules[0].contents[0].nocase);
    }

    #[test]
    fn malformed_missing_sid_is_skipped() {
        let text = r#"alert tcp any any -> any any (msg:"x"; content:"EVIL";)"#;
        let set = compile_rules(text);
        assert!(set.rules.is_empty());
        assert!(set.skipped.iter().any(|s| s.reason.contains("sid")));
    }

    #[test]
    fn quote_aware_semicolon_in_content() {
        let text = r#"alert tcp any any -> any any (msg:"x"; content:"a;b"; sid:9;)"#;
        let set = compile_rules(text);
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].contents[0].pattern, b"a;b");
    }

    #[test]
    fn flowbits_skipped_not_loaded() {
        let text = r#"alert tcp any any -> any any (msg:"fb"; content:"X"; flowbits:set,ET.foo; sid:2000006;)"#;
        let set = compile_rules(text);
        assert!(set.rules.is_empty());
        assert_eq!(set.skipped[0].sid, 2000006);
        assert!(set.skipped[0].reason.contains("flowbits"));
    }

    #[test]
    fn http_uri_sticky_and_pcre_load() {
        let text = r#"
alert http any any -> any any (msg:"uri"; http.uri; content:"/gate.php"; sid:2000002; rev:1;)
alert tcp any any -> any any (msg:"p"; pcre:"/PAY[0-9]{3}/"; sid:2000005;)
"#;
        let set = compile_rules(text);
        assert_eq!(set.rules.len(), 2, "{:?}", set.skipped);
        assert_eq!(set.rules[0].l7.as_deref(), Some("http"));
        assert_eq!(set.rules[0].ops[0].buffer, "http.uri");
        assert_eq!(set.rules[1].ops[0].kind, "pcre");
    }

    #[test]
    fn undefined_var_skips() {
        let text = r#"alert tcp $NO_SUCH_NET any -> any any (msg:"v"; content:"X"; sid:3;)"#;
        let set = compile_rules(text);
        assert!(set.rules.is_empty());
        assert!(set.skipped.iter().any(|s| s.reason.contains("NO_SUCH_NET") || s.reason.contains("var")));
    }

    #[test]
    fn http_servers_alias_loads() {
        let text = r#"alert tcp $HTTP_SERVERS any -> $EXTERNAL_NET any (msg:"h"; content:"X"; sid:77;)"#;
        let set = compile_rules(text);
        assert_eq!(set.rules.len(), 1, "{:?}", set.skipped);
        assert!(set.rules[0].src.contains("10.0.0.0/8"));
    }
}
