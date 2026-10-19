//! Host details that must not leak into the protocol: whether the terminal
//! understands ANSI escapes, and how to close stdout so a reader sees EOF.

/// Enables ANSI escape processing on this host's stderr terminal and reports
/// whether colour should be emitted at all.
///
/// On Unix escapes are always understood by a terminal. Windows consoles only
/// render them after `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is set; older
/// consoles refuse, and then the status line stays plain instead of printing
/// raw escape sequences.
#[cfg(unix)]
pub fn enable_ansi() -> bool {
    true
}

#[cfg(windows)]
pub fn enable_ansi() -> bool {
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
        SetConsoleMode,
    };

    // SAFETY: stderr's handle is owned by the process and only read here;
    // `mode` is a valid out-parameter, and only the VT bit is added back.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(handle, &raw mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// Closes stdout so a downstream reader sees end-of-file, not just a flush.
#[cfg(unix)]
pub fn close_stdout() {
    // SAFETY: fd 1 belongs to this process and the writer is finished with it.
    unsafe { libc::close(1) };
}

/// On Windows a pipe reader sees EOF when the process exits; the runtime owns
/// the standard handles and closing one here would race its own cleanup.
#[cfg(windows)]
pub fn close_stdout() {}
