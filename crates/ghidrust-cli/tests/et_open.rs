//! ET Open --from-archive install + detect using the shipped CLI.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn archive() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let tree = root.join("et-open-mini-tree");
    ghidrust_net_rules::write_mini_et_tree(&tree).expect("tree");
    let bytes = ghidrust_net_rules::tar_gz_dir(&tree).expect("tar");
    let arch = root.join("et-open-mini.tar.gz");
    std::fs::write(&arch, &bytes).expect("write archive");
    let md5 = ghidrust_net_rules::md5_hex_pub(&bytes);
    std::fs::write(root.join("et-open-mini.tar.gz.md5"), md5).expect("md5");
    let http = root.join("et-http-gate.bin");
    std::fs::write(&http, b"GET /gate.php HTTP/1.1\r\nHost: a.test\r\n\r\n").expect("http");
    arch
}

#[test]
fn cli_from_archive_then_detect_gate_php() {
    let arch = archive();
    let dest = std::env::temp_dir().join(format!("et-cli-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dest);
    let out = Command::new(bin())
        .args([
            "net",
            "rules",
            "update",
            "et-open",
            "--from-archive",
            arch.to_str().unwrap(),
            "--dest",
            dest.to_str().unwrap(),
            "--et-version",
            "mini",
            "-json",
        ])
        .env("GHIDRUST_RULES_DIR", dest.display().to_string())
        .output()
        .expect("update");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["loaded"].as_u64().unwrap(), 5, "{v}");
    assert_eq!(v["skipped"].as_u64().unwrap(), 1, "{v}");
    let http = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/et-http-gate.bin");
    let det = Command::new(bin())
        .args([
            "net",
            "detect",
            "--pcap",
            http.to_str().unwrap(),
            "-json",
        ])
        .env("GHIDRUST_RULES_DIR", dest.display().to_string())
        .output()
        .expect("detect");
    assert!(
        det.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&det.stderr)
    );
    let dv: serde_json::Value = serde_json::from_slice(&det.stdout).expect("detect json");
    let alerts = dv["alerts"].as_array().expect("alerts");
    assert!(
        alerts.iter().any(|a| a["sid"].as_u64() == Some(2000002)),
        "{dv}"
    );
}

