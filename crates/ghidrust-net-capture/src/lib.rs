//! Native capture sessions, acquisition backends, and capture-file IO.

pub mod acq;
pub mod file;
pub mod session;

pub use acq::{
    enumerate_os_ifaces, open_live, CaptureBackend, CaptureError, GhidnetcapBackend, IfaceInfo,
    ReplayBackend,
};
pub use file::{read_frames, write_frames, CAPTURE_MAGIC};
pub use session::{
    capture_start, capture_status, capture_stop, flows, list_interfaces, CaptureStartRequest,
    CaptureStartResult,
};
