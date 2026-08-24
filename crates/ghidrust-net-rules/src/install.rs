//! ET Open pack fetch/extract/activate. I/O lives here; compile stays in parse.rs.

use crate::parse::{compile_rules_with, CompiledRuleset};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_ET_VERSION: &str = "7.0.3";
pub const ET_OPEN_BASE: &str = "https://rules.emergingthreats.net/open";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_archive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub et_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_root: Option<String>,
    /// Optional ET Pro oink code — never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub et_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReport {
    pub ok: bool,
    pub path: String,
    pub version: String,
    pub loaded: usize,
    pub skipped: usize,
    pub skip_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivePtr {
    pack: String,
    version: String,
    path: String,
}

pub fn user_rules_root() -> PathBuf {
    if let Ok(p) = std::env::var("GHIDRUST_RULES_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(app) = std::env::var("APPDATA") {
        return PathBuf::from(app).join("ghidrust").join("rules");
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("ghidrust").join("rules");
    }
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        return PathBuf::from(home).join(".ghidrust").join("rules");
    }
    std::env::temp_dir().join("ghidrust-rules")
}

fn active_ptr_path(root: &Path) -> PathBuf {
    root.join("active.json")
}

pub fn active_pack_path() -> Option<PathBuf> {
    let root = user_rules_root();
    let p = active_ptr_path(&root);
    let text = fs::read_to_string(p).ok()?;
    let ptr: ActivePtr = serde_json::from_str(&text).ok()?;
    let path = PathBuf::from(ptr.path);
    if path.is_dir() || path.is_file() {
        Some(path)
    } else {
        None
    }
}

pub fn set_active_pack(path: &Path, version: &str) -> Result<(), String> {
    let root = user_rules_root();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let ptr = ActivePtr {
        pack: "et-open".into(),
        version: version.into(),
        path: path.display().to_string(),
    };
    fs::write(active_ptr_path(&root), serde_json::to_vec_pretty(&ptr).unwrap())
        .map_err(|e| e.to_string())
}

pub fn bundled_minimal_rules() -> PathBuf {
    let cands = [
        PathBuf::from("rules/ghidrust-minimal.rules"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ghidrust-minimal.rules"),
    ];
    for c in cands {
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("rules/ghidrust-minimal.rules")
}

/// Compile active ET pack (all `*.rules` in the dir) plus bundled minimal rules.
pub fn load_active_ruleset() -> Result<CompiledRuleset, String> {
    let mut texts = Vec::new();
    if let Some(p) = active_pack_path() {
        if p.is_dir() {
            collect_rules_dir(&p, &mut texts)?;
        } else if p.is_file() {
            texts.push(fs::read_to_string(&p).map_err(|e| e.to_string())?);
        }
    }
    let mini = bundled_minimal_rules();
    if mini.is_file() {
        texts.push(fs::read_to_string(&mini).map_err(|e| e.to_string())?);
    }
    if texts.is_empty() {
        return Err("no active rules pack".into());
    }
    let vars = {
        let pack = active_pack_path();
        let vp = pack.as_ref().map(|p| {
            if p.is_dir() {
                p.join("ghidrust.vars")
            } else {
                p.parent()
                    .unwrap_or(p)
                    .join("ghidrust.vars")
            }
        });
        match vp {
            Some(p) if p.is_file() => crate::parse::load_vars_file(&p),
            _ => crate::parse::default_vars(),
        }
    };
    Ok(compile_rules_with(&texts.join("\n"), &vars))
}

fn collect_rules_dir(dir: &Path, texts: &mut Vec<String>) -> Result<(), String> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("rules")
                || p.file_name().and_then(|x| x.to_str()) == Some("emerging-all.rules")
        })
        .collect();
    files.sort();
    for p in files {
        texts.push(fs::read_to_string(&p).map_err(|e| e.to_string())?);
    }
    // recurse one level (rules/ subdirectory in ET tarball)
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                collect_rules_dir(&p, texts)?;
            }
        }
    }
    Ok(())
}

pub fn list_rules_json() -> serde_json::Value {
    let active = active_pack_path();
    let set = load_active_ruleset().ok();
    serde_json::json!({
        "packs": {
            "minimal": bundled_minimal_rules().display().to_string(),
            "active": active.as_ref().map(|p| p.display().to_string()),
        },
        "path": active.as_ref().map(|p| p.display().to_string()),
        "version": read_active_version(),
        "loaded": set.as_ref().map(|s| s.rules.len()).unwrap_or(0),
        "skipped": set.as_ref().map(|s| s.skipped.len()).unwrap_or(0),
        "skip_reasons": set.as_ref().map(|s| {
            s.skipped.iter().take(64).map(|x| format!("sid {}: {}", x.sid, x.reason)).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "native": true,
    })
}

fn read_active_version() -> Option<String> {
    let root = user_rules_root();
    let text = fs::read_to_string(active_ptr_path(&root)).ok()?;
    let ptr: ActivePtr = serde_json::from_str(&text).ok()?;
    Some(ptr.version)
}

/// Install ET Open from a local archive (CI) or URL.
pub fn install_et_open(opts: InstallOpts) -> Result<InstallReport, String> {
    let version = opts
        .et_version
        .clone()
        .unwrap_or_else(|| DEFAULT_ET_VERSION.into());
    let root = opts
        .dest_root
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(user_rules_root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let dest = root.join("et-open").join(&version);

    let archive_bytes = if let Some(p) = &opts.from_archive {
        fs::read(p).map_err(|e| format!("archive: {e}"))?
    } else {
        let url = opts.url.clone().unwrap_or_else(|| {
            if let Some(code) = &opts.et_code {
                format!(
                    "https://rules.emergingthreatspro.com/{code}/suricata-{version}/etpro.rules.tar.gz"
                )
            } else {
                format!("{ET_OPEN_BASE}/suricata-{version}/emerging.rules.tar.gz")
            }
        });
        http_get(&url)?
    };

    if let Some(p) = &opts.from_archive {
        let md5_path = PathBuf::from(format!("{p}.md5"));
        if md5_path.is_file() {
            verify_md5(&archive_bytes, &md5_path)?;
        }
    } else if opts.from_archive.is_none() {
        let url = opts.url.clone().unwrap_or_else(|| {
            format!("{ET_OPEN_BASE}/suricata-{version}/emerging.rules.tar.gz")
        });
        let md5_url = format!("{url}.md5");
        match http_get(&md5_url) {
            Ok(sum) => verify_md5_bytes(&archive_bytes, &sum)?,
            Err(e) => {
                return Err(format!("md5 download failed (pack not activated): {e}"));
            }
        }
    }

    if dest.exists() {
        let _ = fs::remove_dir_all(&dest);
    }
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    extract_tar_gz(&archive_bytes, &dest)?;

    let mut texts = Vec::new();
    collect_rules_dir(&dest, &mut texts)?;
    if texts.is_empty() {
        let _ = fs::remove_dir_all(&dest);
        return Err("archive contained no .rules files".into());
    }
    let vp = dest.join("ghidrust.vars");
    if !vp.is_file() {
        let _ = fs::write(
            &vp,
            "HOME_NET: [10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8]\nEXTERNAL_NET: any\nHTTP_SERVERS: $HOME_NET\nSQL_SERVERS: $HOME_NET\nSMTP_SERVERS: $HOME_NET\n",
        );
    }
    let vars = crate::parse::load_vars_file(&vp);
    let set = compile_rules_with(&texts.join("\n"), &vars);
    let skip_reasons: Vec<String> = set
        .skipped
        .iter()
        .take(200)
        .map(|s| format!("sid {}: {}", s.sid, s.reason))
        .collect();
    let report = InstallReport {
        ok: true,
        path: dest.display().to_string(),
        version: version.clone(),
        loaded: set.rules.len(),
        skipped: set.skipped.len(),
        skip_reasons,
        error: None,
        active: true,
    };
    fs::write(
        dest.join("import-report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .ok();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let ptr = ActivePtr {
        pack: "et-open".into(),
        version: version.clone(),
        path: dest.display().to_string(),
    };
    fs::write(active_ptr_path(&root), serde_json::to_vec_pretty(&ptr).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(report)
}

fn verify_md5(bytes: &[u8], md5_path: &Path) -> Result<(), String> {
    let sum = fs::read(md5_path).map_err(|e| e.to_string())?;
    verify_md5_bytes(bytes, &sum)
}

fn verify_md5_bytes(bytes: &[u8], sum_file: &[u8]) -> Result<(), String> {
    let got = md5_hex(bytes);
    let expect = String::from_utf8_lossy(sum_file)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if expect.len() != 32 {
        return Err("md5 file malformed".into());
    }
    if got != expect {
        return Err(format!("hash mismatch (got {got}, expected {expect}); pack not activated"));
    }
    Ok(())
}

fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn md5_hex_pub(bytes: &[u8]) -> String {
    md5_hex(bytes)
}

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    if let Some(rest) = url.strip_prefix("file://") {
        return fs::read(rest).map_err(|e| e.to_string());
    }
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("429") {
                "429 rate limited".into()
            } else {
                s
            }
        })?;
    if resp.status() == 429 {
        return Err("429 rate limited".into());
    }
    if resp.status() >= 400 {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut v = Vec::new();
    resp.into_reader()
        .take(80 * 1024 * 1024)
        .read_to_end(&mut v)
        .map_err(|e| e.to_string())?;
    Ok(v)
}

fn extract_tar_gz(bytes: &[u8], dest: &Path) -> Result<(), String> {
    let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut ar = tar::Archive::new(dec);
    for ent in ar.entries().map_err(|e| e.to_string())? {
        let mut ent = ent.map_err(|e| e.to_string())?;
        let path = ent.path().map_err(|e| e.to_string())?.into_owned();
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }
        let out = dest.join(&path);
        if ent.header().entry_type().is_dir() {
            fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut f = fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut ent, &mut f).map_err(|e| e.to_string())?;
        let _ = f.flush();
    }
    Ok(())
}

/// ET-shaped mini pack used by CI (`--from-archive`).
pub fn write_mini_et_tree(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir.join("rules")).map_err(|e| e.to_string())?;
    fs::write(dir.join("LICENSE"), b"ET Open test fixture - not the Proofpoint ruleset\n")
        .map_err(|e| e.to_string())?;
    fs::write(dir.join("BSD-License.txt"), b"BSD\n").map_err(|e| e.to_string())?;
    fs::write(dir.join("version.txt"), b"mini\n").map_err(|e| e.to_string())?;
    fs::write(
        dir.join("rules").join("et-test.rules"),
        br#"
alert tcp any any -> any any (msg:"ET TEST content"; content:"EVILCMD"; sid:2000001; rev:1;)
alert http any any -> any any (msg:"ET TEST uri"; http.uri; content:"/gate.php"; sid:2000002; rev:1;)
alert tls any any -> any any (msg:"ET TEST sni"; tls.sni; content:"evil.example"; sid:2000003; rev:1;)
alert dns any any -> any any (msg:"ET TEST dns"; dns.query; content:"c2.example"; sid:2000004; rev:1;)
alert tcp any any -> any any (msg:"ET TEST pcre"; pcre:"/PAY[0-9]{3}/"; sid:2000005; rev:1;)
alert tcp any any -> any any (msg:"ET TEST flowbits"; content:"X"; flowbits:set,ET.foo; sid:2000006; rev:1;)
"#,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Build a gzip+tar from a directory (tests / fixture generation).
pub fn tar_gz_dir(dir: &Path) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
        let mut bld = tar::Builder::new(enc);
        bld.append_dir_all(".", dir).map_err(|e| e.to_string())?;
        bld.finish().map_err(|e| e.to_string())?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mini_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "et-mini-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(d.join("rules")).unwrap();
        fs::write(
            d.join("LICENSE"),
            b"ET Open test fixture - not the Proofpoint ruleset\n",
        )
        .unwrap();
        fs::write(d.join("BSD-License.txt"), b"BSD\n").unwrap();
        fs::write(d.join("version.txt"), b"test1\n").unwrap();
        fs::write(
            d.join("rules").join("et-test.rules"),
            br#"
alert tcp any any -> any any (msg:"ET TEST content"; content:"EVILCMD"; sid:2000001; rev:1;)
alert http any any -> any any (msg:"ET TEST uri"; http.uri; content:"/gate.php"; sid:2000002; rev:1;)
alert tls any any -> any any (msg:"ET TEST sni"; tls.sni; content:"evil.example"; sid:2000003; rev:1;)
alert dns any any -> any any (msg:"ET TEST dns"; dns.query; content:"c2.example"; sid:2000004; rev:1;)
alert tcp any any -> any any (msg:"ET TEST pcre"; pcre:"/PAY[0-9]{3}/"; sid:2000005; rev:1;)
alert tcp any any -> any any (msg:"ET TEST flowbits"; content:"X"; flowbits:set,ET.foo; sid:2000006; rev:1;)
"#,
        )
        .unwrap();
        d
    }

    #[test]
    fn from_archive_loads_and_skips_flowbits() {
        let dir = mini_dir();
        let bytes = tar_gz_dir(&dir).unwrap();
        let arch = dir.join("et-open-mini.tar.gz");
        fs::write(&arch, &bytes).unwrap();
        let md5 = md5_hex(&bytes);
        fs::write(dir.join("et-open-mini.tar.gz.md5"), md5.as_bytes()).unwrap();
        let dest = dir.join("out");
        let rep = install_et_open(InstallOpts {
            from_archive: Some(arch.display().to_string()),
            dest_root: Some(dest.display().to_string()),
            et_version: Some("mini".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(rep.ok);
        assert_eq!(rep.loaded, 5, "flowbits skipped, others loaded: {:?}", rep.skip_reasons);
        assert_eq!(rep.skipped, 1);
        assert!(rep.skip_reasons.iter().any(|s| s.contains("2000006") && s.contains("flowbits")));
        assert!(Path::new(&rep.path).join("LICENSE").is_file() || Path::new(&rep.path).join("rules").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_md5_does_not_activate() {
        let dir = mini_dir();
        let bytes = tar_gz_dir(&dir).unwrap();
        let arch = dir.join("bad.tar.gz");
        fs::write(&arch, &bytes).unwrap();
        fs::write(dir.join("bad.tar.gz.md5"), b"00000000000000000000000000000000\n").unwrap();
        let dest = dir.join("out-bad");
        let err = install_et_open(InstallOpts {
            from_archive: Some(arch.display().to_string()),
            dest_root: Some(dest.display().to_string()),
            et_version: Some("bad".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("hash mismatch"), "{err}");
        assert!(!dest.join("et-open").join("bad").join("import-report.json").is_file());
        let _ = fs::remove_dir_all(&dir);
    }
}
