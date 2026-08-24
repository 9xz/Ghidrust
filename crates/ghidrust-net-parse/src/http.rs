//! Minimal HTTP/1.x request pivot parse.

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub host: Option<String>,
    /// Raw header block (name: value lines, no request-line).
    pub headers: String,
}

pub fn parse_request(data: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let r = parse_request_ex(data)?;
    let host = r.host.clone();
    let uri = if r.uri.is_empty() {
        None
    } else {
        Some(r.uri)
    };
    if host.is_none() && uri.is_none() {
        None
    } else {
        Some((host, uri))
    }
}

pub fn parse_request_ex(data: &[u8]) -> Option<HttpRequest> {
    let s = std::str::from_utf8(data).ok()?;
    let mut out = HttpRequest::default();
    let mut hdr = String::new();
    for (idx, line) in s.split("\r\n").enumerate() {
        if idx == 0 {
            let mut parts = line.split_whitespace();
            let method = parts.next()?;
            if !matches!(
                method,
                "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" | "PATCH"
            ) {
                return None;
            }
            out.method = method.to_string();
            out.uri = parts.next().unwrap_or("").to_string();
        } else if line.is_empty() {
            break;
        } else {
            if let Some(rest) = line.strip_prefix("Host:") {
                out.host = Some(rest.trim().to_string());
            }
            hdr.push_str(line);
            hdr.push('\n');
        }
    }
    out.headers = hdr;
    if out.method.is_empty() {
        None
    } else {
        Some(out)
    }
}
