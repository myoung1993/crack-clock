//! Reads a password from stdin, hiding the input when stdin is an
//! interactive terminal. When stdin is piped or redirected (a file, another
//! program's output) there's no terminal echo to suppress, so that case
//! just reads everything through unchanged.

use std::io::{self, Read, Write};

pub fn read_password() -> io::Result<String> {
    if imp::stdin_is_tty() {
        eprint!("password (input hidden): ");
        io::stderr().flush()?;
        let result = imp::read_line_without_echo();
        eprintln!();
        result
    } else {
        eprintln!("reading password from stdin (input will be visible)");
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(trim_line_ending(&input))
    }
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

#[cfg(not(unix))]
mod imp {
    use std::io;

    /// No echo-suppression support outside Unix yet, so `read_password`
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
