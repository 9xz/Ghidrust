//! Hand-rolled live acquisition (ghidnetcap).
//!
//! Reference (not linked): Npcap Packet32 `PacketOpenAdapter` / `PacketReceivePacket`,
//! libpcap `pcap_findalldevs` / `pcap_open_live` / `pcap_next_ex`, WinPcap NPF
//! `\\.\NPCAP\{guid}` + `ReadFile`, and Windows `SIO_RCVALL` raw sockets.
//!
//! Cargo does **not** link npcap/wpcap/Packet.dll. NPF is optional runtime
//! `CreateFile` if a driver is installed; otherwise IPv4 raw sockets.

use super::{CaptureBackend, CaptureError};
use crate::acq::pkt::decode_packet;
use ghidrust_net_flow::now_ms;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceInfo {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

/// OS adapters (empty on enum failure). Never includes the synthetic `replay` row.
pub fn enumerate_os_ifaces() -> Vec<IfaceInfo> {
    #[cfg(windows)]
    {
        win::enumerate()
    }
    #[cfg(not(windows))]
    {
        unix_sysfs_ifaces()
    }
}

/// Open a live iface. `None` / `"live"` / empty → first IPv4 adapter.
///
/// Fail-closed: `privilege_required` or `backend_unavailable`. Never fabricates frames.
pub fn open_live(iface: Option<&str>) -> Result<GhidnetcapBackend, CaptureError> {
    if std::env::var("GHIDRUST_NET_LIVE_STUB").ok().as_deref() == Some("1") {
        return Err(CaptureError::unavailable(
            "GHIDRUST_NET_LIVE_STUB=1 selects LiveStubBackend, not ghidnetcap",
        ));
    }
    let want = iface.map(str::trim).filter(|s| !s.is_empty() && *s != "live");
    if matches!(want, Some("replay")) {
        return Err(CaptureError::unavailable("replay iface requires replay_path"));
    }
    #[cfg(windows)]
    {
        win::open(want)
    }
    #[cfg(not(windows))]
    {
        unix_open(want)
    }
}

pub struct GhidnetcapBackend {
    label: String,
    inner: Inner,
}

impl std::fmt::Debug for GhidnetcapBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhidnetcapBackend")
            .field("label", &self.label)
            .finish()
    }
}

enum Inner {
    #[cfg(windows)]
    Raw { sock: usize },
    #[cfg(windows)]
    Npf { handle: *mut std::ffi::c_void },
    #[cfg(not(windows))]
    Packet { fd: i32 },
}

// NPF HANDLE is used only on the capture thread.
unsafe impl Send for GhidnetcapBackend {}

impl CaptureBackend for GhidnetcapBackend {
    fn poll_frames(&mut self) -> Result<Vec<FrameWrap>, CaptureError> {
        self.poll_inner()
    }
    fn name(&self) -> &str {
        &self.label
    }
}

// Trait uses Frame — alias to keep this file compiling against CaptureBackend.
use ghidrust_net_flow::Frame as FrameWrap;

impl GhidnetcapBackend {
    fn poll_inner(&mut self) -> Result<Vec<FrameWrap>, CaptureError> {
        #[cfg(windows)]
        {
            win::poll(self)
        }
        #[cfg(not(windows))]
        {
            unix_poll(self)
        }
    }
}

impl Drop for GhidnetcapBackend {
    fn drop(&mut self) {
        #[cfg(windows)]
        win::close(self);
        #[cfg(not(windows))]
        unix_close(self);
    }
}

#[cfg(not(windows))]
fn unix_sysfs_ifaces() -> Vec<IfaceInfo> {
    let path = std::path::Path::new("/sys/class/net");
    let Ok(rd) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .map(|name| IfaceInfo {
            description: format!("sysfs {name}"),
            name: name.clone(),
            ipv4: None,
            guid: None,
        })
        .collect()
}

#[cfg(not(windows))]
fn unix_open(_want: Option<&str>) -> Result<GhidnetcapBackend, CaptureError> {
    Err(CaptureError::unavailable(
        "AF_PACKET live capture is not enabled on this host; use replay",
    ))
}

#[cfg(not(windows))]
fn unix_poll(_b: &mut GhidnetcapBackend) -> Result<Vec<FrameWrap>, CaptureError> {
    Ok(Vec::new())
}

#[cfg(not(windows))]
fn unix_close(_b: &mut GhidnetcapBackend) {}

#[cfg(windows)]
mod win {
    use super::*;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;

    type Handle = *mut std::ffi::c_void;
    type Dword = u32;
    type Socket = usize;

    const INVALID_SOCKET: Socket = !0;
    const SOCKET_ERROR: i32 = -1;
    const AF_INET: i32 = 2;
    const SOCK_RAW: i32 = 3;
    const IPPROTO_IP: i32 = 0;
    const SIO_RCVALL: i32 = -1744830463; // 0x98000001 as i32
    const RCVALL_ON: u32 = 1;
    const FIONBIO: i32 = -2147195266; // 0x8004667E
    const WSAEACCES: i32 = 10013;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEADDRNOTAVAIL: i32 = 10049;
    const GENERIC_READ: Dword = 0x8000_0000;
    const GENERIC_WRITE: Dword = 0x4000_0000;
    const OPEN_EXISTING: Dword = 3;
    const FILE_ATTRIBUTE_NORMAL: Dword = 0x80;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const ERROR_ACCESS_DENIED: Dword = 5;

    #[repr(C)]
    struct WsaData {
        w_version: u16,
        w_high: u16,
        sz_desc: [u8; 257],
        sz_sys: [u8; 129],
        max_sockets: u16,
        max_udp: u16,
        vendor: *mut u8,
    }

    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    struct IpAddrString {
        next: *mut IpAddrString,
        ip_address: [u8; 16],
        ip_mask: [u8; 16],
        context: Dword,
    }

    #[repr(C)]
    struct IpAdapterInfo {
        next: *mut IpAdapterInfo,
        combo_index: Dword,
        adapter_name: [u8; 260],
        description: [u8; 132],
        address_length: u32,
        address: [u8; 8],
        index: Dword,
        typ: u32,
        dhcp_enabled: u32,
        current_ip: *mut IpAddrString,
        ip_address_list: IpAddrString,
        gateway_list: IpAddrString,
        dhcp_server: IpAddrString,
        have_wins: i32,
        primary_wins: IpAddrString,
        secondary_wins: IpAddrString,
        lease_obtained: i64,
        lease_expires: i64,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersInfo(p: *mut IpAdapterInfo, len: *mut Dword) -> Dword;
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAStartup(ver: u16, data: *mut WsaData) -> i32;
        fn socket(af: i32, typ: i32, proto: i32) -> Socket;
        fn bind(s: Socket, addr: *const SockAddrIn, len: i32) -> i32;
        fn closesocket(s: Socket) -> i32;
        fn recv(s: Socket, buf: *mut u8, len: i32, flags: i32) -> i32;
        fn ioctlsocket(s: Socket, cmd: i32, arg: *mut u32) -> i32;
        fn WSAIoctl(
            s: Socket,
            code: i32,
            inbuf: *const u8,
            inlen: Dword,
            outbuf: *mut u8,
            outlen: Dword,
            ret: *mut Dword,
            overlapped: *mut u8,
            completion: *mut u8,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: Dword,
            share: Dword,
            sa: *mut u8,
            disp: Dword,
            flags: Dword,
            tmpl: Handle,
        ) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn ReadFile(
            h: Handle,
            buf: *mut u8,
            n: Dword,
            read: *mut Dword,
            overlapped: *mut u8,
        ) -> i32;
        fn GetLastError() -> Dword;
    }

    fn wsa_once() -> Result<(), CaptureError> {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        let mut rc = 0i32;
        ONCE.call_once(|| unsafe {
            let mut d: WsaData = zeroed();
            rc = WSAStartup(0x0202, &mut d);
        });
        if rc != 0 {
            return Err(CaptureError::unavailable(format!("WSAStartup {rc}")));
        }
        Ok(())
    }

    fn cstr(buf: &[u8]) -> String {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    pub fn enumerate() -> Vec<IfaceInfo> {
        unsafe {
            let mut len: Dword = 0;
            GetAdaptersInfo(null_mut(), &mut len);
            if len == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; len as usize];
            let rc = GetAdaptersInfo(buf.as_mut_ptr() as *mut IpAdapterInfo, &mut len);
            if rc != 0 {
                return Vec::new();
            }
            let mut out = Vec::new();
            let base = buf.as_ptr() as usize;
            let mut p = buf.as_ptr() as usize;
            let end = base + buf.len();
            // MSVC x64 IP_ADAPTER_INFO: Next@0, ComboIndex@8, AdapterName@12 (260),
            // Description@272 (132), … IpAddressList.IpAddress after pointer-aligned hole.
            const NAME: usize = 12;
            const DESC: usize = 272;
            const IP_ADDR: usize = 448; // IpAddressList.IpAddress after Next pointer
            while p >= base && p + IP_ADDR + 16 <= end {
                let off = p - base;
                let guid = cstr(&buf[off + NAME..off + NAME + 260]);
                let desc = cstr(&buf[off + DESC..off + DESC + 132]);
                let ip = cstr(&buf[off + IP_ADDR..off + IP_ADDR + 16]);
                let ipv4 = if ip.is_empty() || ip == "0.0.0.0" {
                    None
                } else {
                    Some(ip)
                };
                let name = if guid.is_empty() {
                    desc.clone()
                } else {
                    guid.clone()
                };
                if !name.is_empty() {
                    out.push(IfaceInfo {
                        name,
                        description: desc,
                        ipv4,
                        guid: if guid.is_empty() { None } else { Some(guid) },
                    });
                }
                let next = usize::from_le_bytes(buf[off..off + 8].try_into().unwrap());
                if next == 0 || next == p {
                    break;
                }
                p = next;
            }
            out
        }
    }

    fn pick(want: Option<&str>) -> Result<IfaceInfo, CaptureError> {
        let ifaces = enumerate();
        if ifaces.is_empty() {
            return Err(CaptureError::unavailable("GetAdaptersInfo returned no adapters"));
        }
        if let Some(w) = want {
            ifaces
                .into_iter()
                .find(|i| {
                    i.name.eq_ignore_ascii_case(w)
                        || i.description.to_ascii_lowercase().contains(&w.to_ascii_lowercase())
                        || i.guid.as_deref().is_some_and(|g| g.eq_ignore_ascii_case(w))
                })
                .ok_or_else(|| CaptureError::unavailable(format!("no such iface: {w}")))
        } else {
            ifaces
                .into_iter()
                .find(|i| i.ipv4.is_some())
                .ok_or_else(|| CaptureError::unavailable("no IPv4 adapter"))
        }
    }

    fn ipv4_to_s_addr(s: &str) -> Option<u32> {
        let mut o = [0u8; 4];
        let parts: Vec<_> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        for (i, p) in parts.iter().enumerate() {
            o[i] = p.parse().ok()?;
        }
        Some(u32::from_be_bytes(o).to_be()) // s_addr is in network order, stored as u32
    }

    fn try_npf(guid: &str) -> Result<Handle, CaptureError> {
        let g = guid.trim_matches(|c| c == '{' || c == '}');
        let paths = [
            format!("\\\\.\\NPCAP\\{{{g}}}"),
            format!("\\\\.\\NPF_{{{g}}}"),
            format!("\\\\.\\NPCAP\\{guid}"),
            format!("\\\\.\\NPF_{guid}"),
        ];
        unsafe {
            for p in &paths {
                let wide: Vec<u16> = p.encode_utf16().chain(std::iter::once(0)).collect();
                let h = CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                );
                if h != INVALID_HANDLE_VALUE && !h.is_null() {
                    return Ok(h);
                }
                let err = GetLastError();
                if err == ERROR_ACCESS_DENIED {
                    return Err(CaptureError::privilege());
                }
            }
        }
        Err(CaptureError::unavailable("NPF/Npcap device not present"))
    }

    fn try_raw(ipv4: &str) -> Result<Socket, CaptureError> {
        wsa_once()?;
        let addr = ipv4_to_s_addr(ipv4).ok_or_else(|| {
            CaptureError::unavailable(format!("bad ipv4 {ipv4}"))
        })?;
        unsafe {
            let s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
            if s == INVALID_SOCKET {
                let e = WSAGetLastError();
                return Err(if e == WSAEACCES {
                    CaptureError::privilege()
                } else {
                    CaptureError::unavailable(format!("socket SOCK_RAW: WSA{e}"))
                });
            }
            let sa = SockAddrIn {
                family: AF_INET as u16,
                port: 0,
                addr,
                zero: [0; 8],
            };
            if bind(s, &sa, size_of::<SockAddrIn>() as i32) == SOCKET_ERROR {
                let e = WSAGetLastError();
                closesocket(s);
                return Err(if e == WSAEACCES || e == WSAEADDRNOTAVAIL {
                    CaptureError::privilege()
                } else {
                    CaptureError::unavailable(format!("bind: WSA{e}"))
                });
            }
            let on: u32 = RCVALL_ON;
            let mut ret: Dword = 0;
            if WSAIoctl(
                s,
                SIO_RCVALL,
                &on as *const u32 as *const u8,
                4,
                null_mut(),
                0,
                &mut ret,
                null_mut(),
                null_mut(),
            ) == SOCKET_ERROR
            {
                let e = WSAGetLastError();
                closesocket(s);
                return Err(if e == WSAEACCES {
                    CaptureError::privilege()
                } else {
                    CaptureError::unavailable(format!("SIO_RCVALL: WSA{e}"))
                });
            }
            let mut nb: u32 = 1;
            let _ = ioctlsocket(s, FIONBIO, &mut nb);
            Ok(s)
        }
    }

    pub fn open(want: Option<&str>) -> Result<GhidnetcapBackend, CaptureError> {
        let info = pick(want)?;
        if let Some(g) = &info.guid {
            match try_npf(g) {
                Ok(h) => {
                    return Ok(GhidnetcapBackend {
                        label: format!("ghidnetcap-npf:{}", info.name),
                        inner: Inner::Npf { handle: h },
                    });
                }
                Err(e) if e.code == "privilege_required" => return Err(e),
                Err(_) => {}
            }
        }
        let ip = info
            .ipv4
            .as_deref()
            .ok_or_else(|| CaptureError::unavailable("adapter has no IPv4 for SIO_RCVALL"))?;
        let sock = try_raw(ip)?;
        Ok(GhidnetcapBackend {
            label: format!("ghidnetcap-raw:{}", info.name),
            inner: Inner::Raw { sock },
        })
    }

    pub fn poll(b: &mut GhidnetcapBackend) -> Result<Vec<FrameWrap>, CaptureError> {
        let mut out = Vec::new();
        let ts = now_ms();
        match &mut b.inner {
            Inner::Raw { sock } => unsafe {
                let mut buf = [0u8; 65535];
                for _ in 0..32 {
                    let n = recv(*sock, buf.as_mut_ptr(), buf.len() as i32, 0);
                    if n == SOCKET_ERROR {
                        let e = WSAGetLastError();
                        if e == WSAEWOULDBLOCK {
                            break;
                        }
                        if e == WSAEACCES {
                            return Err(CaptureError::privilege());
                        }
                        return Err(CaptureError::unavailable(format!("recv WSA{e}")));
                    }
                    if n <= 0 {
                        break;
                    }
                    if let Some(f) = decode_packet(ts, &buf[..n as usize]) {
                        out.push(f);
                    }
                }
            },
            Inner::Npf { handle } => unsafe {
                let mut buf = [0u8; 65535];
                let mut read: Dword = 0;
                let ok = ReadFile(*handle, buf.as_mut_ptr(), buf.len() as Dword, &mut read, null_mut());
                if ok == 0 {
                    let e = GetLastError();
                    if e == 997 || e == 0 || e == 234 {
                        // pending / EOF-ish — no frames this poll
                        return Ok(out);
                    }
                    if e == ERROR_ACCESS_DENIED {
                        return Err(CaptureError::privilege());
                    }
                    return Err(CaptureError::unavailable(format!("NPF ReadFile {e}")));
                }
                // bpf_hdr: tv_sec i32, tv_usec i32, caplen u32, datalen u32, hdrlen u16 (+ pad)
                if read >= 18 {
                    let caplen = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
                    let hdrlen = u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize;
                    let start = if hdrlen >= 18 && hdrlen < read as usize {
                        hdrlen
                    } else {
                        18
                    };
                    let end = (start + caplen).min(read as usize);
                    if end > start {
                        if let Some(f) = decode_packet(ts, &buf[start..end]) {
                            out.push(f);
                        }
                    }
                }
            },
        }
        Ok(out)
    }

    pub fn close(b: &mut GhidnetcapBackend) {
        match &b.inner {
            Inner::Raw { sock } => unsafe {
                let _ = closesocket(*sock);
            },
            Inner::Npf { handle } => unsafe {
                let _ = CloseHandle(*handle);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_enum_is_not_only_placeholders() {
        let os = enumerate_os_ifaces();
        // When the OS returns adapters, none of this list is the synthetic pair.
        for i in &os {
            assert_ne!(i.name, "replay");
        }
        if cfg!(windows) {
            // GetAdaptersInfo almost always yields at least Loopback on Windows.
            // If it is empty, live-open must still be honest (covered below).
            let names: Vec<_> = os.iter().map(|i| i.name.as_str()).collect();
            assert!(
                !names.is_empty() || open_live(None).is_err(),
                "empty OS enum must not pretend live capture works"
            );
        }
    }

    #[test]
    fn live_open_unknown_iface_is_unavailable() {
        let err = open_live(Some("no-such-ghidnetcap-iface-xyz")).unwrap_err();
        assert!(
            err.code == "backend_unavailable" || err.code == "privilege_required",
            "{}",
            err.code
        );
    }

    #[test]
    fn live_open_does_not_emit_stub_payload() {
        match open_live(None) {
            Ok(mut b) => {
                let frames = b.poll_frames().unwrap_or_default();
                for f in frames {
                    assert_ne!(
                        f.payload.as_slice(),
                        b"live-stub",
                        "ghidnetcap must not fabricate the live-stub frame"
                    );
                }
            }
            Err(e) => {
                assert!(
                    e.code == "privilege_required" || e.code == "backend_unavailable",
                    "honest error, got {}",
                    e.code
                );
            }
        }
    }
}
