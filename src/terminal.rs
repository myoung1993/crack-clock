//! Reads a password from stdin, hiding the input when stdin is an
//! interactive terminal. When stdin is piped or redirected (a file, another
//! program's output) there's no terminal echo to suppress, so that case
//! just reads everything through unchanged.

use std::io::{self, Read, Write};

/// Hidden input can't be glanced at before submitting, so a mistyped
/// character is otherwise invisible until the analysis comes back for the
/// wrong password. Asking twice and requiring a match catches that; capping
/// it at a few attempts avoids trapping a user who genuinely can't type the
/// same thing twice (e.g. a long passphrase) in an endless loop.
const MAX_ATTEMPTS: u32 = 3;

pub fn read_password() -> io::Result<String> {
    if imp::stdin_is_tty() {
        for attempt in 1..=MAX_ATTEMPTS {
            let first = prompt_hidden("password (input hidden): ")?;
            let second = prompt_hidden("confirm password: ")?;
            if first == second {
                return Ok(first);
            }
            if attempt < MAX_ATTEMPTS {
                eprintln!("passwords didn't match, try again");
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("passwords didn't match after {} attempts", MAX_ATTEMPTS),
        ))
    } else {
        eprintln!("reading password from stdin (input will be visible)");
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(trim_line_ending(&input))
    }
}

fn prompt_hidden(prompt: &str) -> io::Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;
    let result = imp::read_line_without_echo();
    eprintln!();
    result
}

fn trim_line_ending(s: &str) -> String {
    s.trim_end_matches(['\n', '\r']).to_string()
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::process::{Command, Stdio};

    extern "C" {
        fn isatty(fd: i32) -> i32;
    }

    pub fn stdin_is_tty() -> bool {
        unsafe { isatty(0) != 0 }
    }

    /// Disables terminal echo, reads one line, then restores echo - even if
    /// the read fails. This shells out to `stty` instead of binding termios
    /// directly: the termios struct layout (field order, `c_cc` length)
    /// differs between Linux and macOS, and a wrong binding would corrupt
    /// terminal state rather than just fail to compile.
    pub fn read_line_without_echo() -> io::Result<String> {
        let echo_was_disabled = set_echo(false).is_ok();
        let result = read_line();
        if echo_was_disabled {
            let _ = set_echo(true);
        }
        result
    }

    fn set_echo(enabled: bool) -> io::Result<()> {
        let flag = if enabled { "echo" } else { "-echo" };
        let status = Command::new("stty")
            .arg(flag)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "stty exited with an error"))
        }
    }

    fn read_line() -> io::Result<String> {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(super::trim_line_ending(&line))
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;

    type Handle = *mut c_void;

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // (DWORD)-10
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> Handle;
        fn GetConsoleMode(hConsoleHandle: Handle, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: Handle, dwMode: u32) -> i32;
    }

    fn stdin_handle() -> Option<Handle> {
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle as isize == -1 {
            None
        } else {
            Some(handle)
        }
    }

    fn console_mode(handle: Handle) -> Option<u32> {
        let mut mode: u32 = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
            Some(mode)
        } else {
            None
        }
    }

    /// A console handle only reports a mode when stdin is an actual console,
    /// not a pipe or redirected file, so this doubles as the tty check.
    pub fn stdin_is_tty() -> bool {
        stdin_handle().and_then(console_mode).is_some()
    }

    /// Clears `ENABLE_ECHO_INPUT` on the console while keeping the rest of
    /// the mode (line buffering, processed input) intact, reads one line,
    /// then restores the original mode - even if the read fails.
    pub fn read_line_without_echo() -> io::Result<String> {
        let handle = stdin_handle();
        let original_mode = handle.and_then(console_mode);

        let echo_was_disabled = match (handle, original_mode) {
            (Some(h), Some(mode)) => {
                unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) != 0 }
            }
            _ => false,
        };

        let result = read_line();

        if echo_was_disabled {
            if let (Some(h), Some(mode)) = (handle, original_mode) {
                unsafe {
                    SetConsoleMode(h, mode);
                }
            }
        }

        result
    }

    fn read_line() -> io::Result<String> {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(super::trim_line_ending(&line))
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;

    /// No echo-suppression support on this platform, so `read_password`
    /// always falls back to its visible-input path here.
    pub fn stdin_is_tty() -> bool {
        false
    }

    pub fn read_line_without_echo() -> io::Result<String> {
        unreachable!("stdin_is_tty() always returns false on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_line_ending_strips_trailing_newline_variants() {
        assert_eq!(trim_line_ending("hunter2\n"), "hunter2");
        assert_eq!(trim_line_ending("hunter2\r\n"), "hunter2");
        assert_eq!(trim_line_ending("hunter2"), "hunter2");
        assert_eq!(trim_line_ending("hunter2\n\n"), "hunter2");
    }
}
