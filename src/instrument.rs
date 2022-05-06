#[cfg(target_os = "windows")]
use superluminal_perf::*;

// IO: Red
pub const E_RECV_COLOR: u32 = 0xFF6D6DFF;
pub const E_SEND_COLOR: u32 = 0xFF6D6DFF;

// COMPUTATION: Yellow
pub const E_COMP_COLOR: u32 = 0xFFFF6DFF;

// FUNCTION: Blue
pub const E_FUNC_COLOR: u32 = 0x1f1f91FF;

// PROTOCOL: Green
pub const E_PROT_COLOR: u32 = 0x6DFF6DFF;

#[inline(always)]
#[cfg(target_os = "windows")]
pub fn begin(name: &str, color: u32) {
    begin_event_with_color(name, color);
}

#[inline(always)]
#[cfg(not(target_os = "windows"))]
pub fn begin(name: &str, color: u32) {}

#[inline(always)]
#[cfg(target_os = "windows")]
pub fn end() {
    end_event();
}

#[inline(always)]
#[cfg(not(target_os = "windows"))]
pub fn end() {}
