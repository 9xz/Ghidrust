# Ghidnet — native network investigation (`tool_surface >= 8`)

In-tree **attribute → detect → dig**. No Suricata binary, no `suricata-update`, no Npcap crate, no vendored ET tarball. Prefer MCP or GUI for multi-step sessions (`session_id` is process-local; CLI one-shot cannot reuse it). Check `server_info.network` (`native`, `wave`, `caps` include `et-open` / `ids`, `capture`).

## Surfaces

| Surface | Entry |
|---------|--------|
| MCP | `net_*` tools; `net_rules_update` for ET Open |
| CLI | `ghidrust net help` — `dig\|playbook\|connections\|owners\|ifaces\|capture\|flows\|detect\|alerts\|rules\|pivots … [--json]` |
| GUI | **Network** menu / **Window → Network** — tabs Connections \| Capture \| Alerts \| Rules \| Dig |
| Helper bin | `target/release/ghidrust-netcap` |
| Bundled GNR | `rules/ghidrust-minimal.rules` (always merged into the active pack) |
| Active pack | `GHIDRUST_RULES_DIR` or `%APPDATA%/ghidrust/rules` / `~/.ghidrust/rules` (`et-open/<version>/` + `active.json`) |

CLI, GUI **Download / update ET Open**, and MCP `net_rules_update` share **`install_et_open`**. Detect without an explicit rules path uses **`load_active_ruleset`** (ET pack + minimal).

## MCP tools

| Tool | Args (common) | Notes |
|------|----------------|-------|
| `net_dig` | `path`, `pid`, `host`, `ioc`, `alert_id`, `execute`, `live` | Compile/execute playbook; closed-loop from alert |
| `net_playbook` | same hint fields | Plan only (MCP chain shape) |
| `net_connections` | `pid`, `path`, `proto`, `max` | Socket → owner; airgap refuses |
| `net_owners` | `pid` | Owner detail |
| `net_ifaces` | — | OS adapters (ghidnetcap) + replay |
| `net_capture_start` | `iface`, `filter`, `pid`, `path`, `out`, `replay_path` | Returns `session_id`. Live: fail-closed `privilege_required` |
| `net_capture_stop` / `net_capture_status` | `session_id` | |
| `net_flows` | `session_id`, `max` | Attributed flows |
| `net_detect` | `pcap`, optional `rules` | Omit `rules` → active ET pack + minimal. IDS records only |
| `net_alerts` | `max` | Severity queue |
| `net_rules_list` | — | `packs.minimal` / `packs.active`, `loaded`, `skipped`, `skip_reasons` |
| `net_rules_update` | `from_archive`, `url`, `et_version`, `dest` | Fetch/install ET Open; activate pack |
| `net_rules_load` / `net_rules_check` | `path` | Compile-check one file (`rule_count`, `skipped`) |
| `net_pivots` | `pcap` | DNS / TLS SNI / HTTP / SMB fields |
| `net_job_get` | `job_id` | **Stub** today (`status: unknown`) — do not rely on async jobs |

## ET Open

Proofpoint Emerging Threats Open rules are compiled **as written**. Unimplemented keywords skip that SID (honest `skipped` count) — do not rewrite ET text.

```bash
ghidrust net rules update et-open --json
ghidrust net rules update et-open --from-archive fixtures/et-open-mini.tar.gz --et-version mini --dest DIR --json
ghidrust net rules list --json
```

MCP: `net_rules_update` `{}` (online) or `{ "from_archive": "…", "et_version": "mini", "dest": "…" }`. GUI: Rules tab **Download / update ET Open**.

Default fetch: `https://rules.emergingthreats.net/open` (`emerging.rules.tar.gz` + `.md5`, version `7.0.3` unless `et_version` set). Optional `et_code` is an ET Pro oink — never log it.

## Detect / IDS vs IPS

Actions `alert`, `pass`, and `drop` are **recorded as alerts**. `drop` is not a kernel/NFQUEUE/WFP block. Inline block stays off unless `GHIDRUST_NET_INLINE=1`.

**Loaded:** `content` / `pcre`, `nocase`, `distance`/`within` (cursor = previous hit end), sticky buffers `http.uri`/`http.host`/`http.method`/`http.header` / `dns.query` / `tls.sni`, `flow:established|to_server|to_client`, `$HOME_NET` / `$HTTP_SERVERS` / CIDR.

**Skipped SIDs:** `flowbits`/`xbits`/`flowint`, `ja3`/`ja3s`, `lua`, `threshold`/`detection_filter`, `file-data`, `byte_test`/`byte_jump`, unknown `http.*`/`tls.*` buffers.

```bash
ghidrust net detect --pcap capture.grncap --json
ghidrust net detect --payload-file fixtures/et-http-gate.bin --json
ghidrust net detect --pcap capture.grncap --rules rules/ghidrust-minimal.rules --json
```

## Capture (ghidnetcap)

`net ifaces` lists real OS adapters plus `replay`. Live open uses Windows NPF `CreateFile` when a driver is present, else `SIO_RCVALL` raw sockets; Unix packet sockets. Cargo does not link Npcap. Unprivileged live open returns `privilege_required` — never empty fabricated frames. `GHIDRUST_NET_LIVE_STUB=1` errors on live open (tests only). Prefer `replay_path` in CI.

## Workflows

1. **Connections → Dig:** `net_connections` → pick remote/image → `net_dig` with `path` + `host`/`ioc` + `execute`.
2. **Capture → Dig:** `net_ifaces` → `net_capture_start` (`replay_path` in CI) → `net_flows` → `net_capture_stop` → dig owner `path`.
3. **ET Open → Detect → Dig:** `net_rules_update` → `net_rules_list` (inspect `skipped`) → `net_detect` (no `rules`) → `net_dig` with `alert_id` (+ `path` if alert has no owner).
4. **Pivots → Dig:** `net_pivots` → feed DNS/SNI/HTTP/SMB host into `net_dig` `host`/`ioc`.
5. **GUI:** Rules **Download / update ET Open**; Connections/Capture **Dig** → Dig tab **Compile**/**Execute** → **Open in Listing**. Capture **Export path** reveals `out_path`. **Inline block** disabled unless `GHIDRUST_NET_INLINE=1|true`.

## Honesty

- Never invent hosts/IOCs; `pid_confidence=unknown` is not ground truth.
- Airgap: refuses `net_connections` / `net_owners` / `net_ifaces` / `net_capture_*` / `net_flows` / `net_detect`; path-only `net_dig` / `net_playbook` allowed. ET install in airgap: `from_archive` only.
- Do not install Suricata/Wireshark/Npcap crates as a substitute — engines are `ghidrust-net-*`.
- Do not claim Suricata-complete matching or kernel IPS. Empty detect after a large `skipped` count is honest, not a silent miss of those SIDs.
- `net_job_get` is a stub.
