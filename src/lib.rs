//! Core estimate used by the crackclock CLI.
//!
//! The question this answers: given a password, roughly how long would it
//! take an attacker to find it by guessing? There is no way to do this
//! exactly without knowing the attacker's method, so this uses a standard
//! shortcut: estimate the effective size of the search space (entropy), then
//! divide by a guessing rate for a few realistic attack scenarios.
//!
//! The entropy estimate starts from character-class variety (an assumption
//! that the attacker doesn't know anything about the password except its
//! length and alphabet) and then gets knocked down hard whenever the
//! password contains a pattern a real attacker's tooling would try first:
//! a repeated character, a run of consecutive characters, a keyboard walk,
//! or an exact match against a small list of passwords everyone tries.

use std::collections::HashSet;

/// A list of passwords that show up at or near the top of every leaked
/// password corpus. Matching one of these means the true search space is
/// "how far down this list is it", not "26^length" - so entropy gets
/// clamped to log2(this list's size) rather than computed from length.
const COMMON_PASSWORDS: [&str; 15] = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "111111",
    "1234567", "letmein", "password1", "iloveyou", "admin", "welcome", "monkey",
];

/// Result of analyzing one password.
pub struct Analysis {
    pub length: usize,
    pub pool_size: u32,
    pub entropy_bits: f64,
    pub notes: Vec<String>,
}

impl Analysis {
    /// Seconds to exhaust the estimated search space at a given guess rate.
    pub fn crack_time_seconds(&self, guesses_per_second: f64) -> f64 {
        2f64.powf(self.entropy_bits) / guesses_per_second
    }
}

/// One attack scenario: how fast an attacker can submit guesses.
pub struct Scenario {
    pub name: &'static str,
    pub guesses_per_second: f64,
}

/// A handful of rough, commonly cited guessing rates. These are not
/// precise for any specific system - they exist to give a sense of scale
/// across a throttled login form up to an offline GPU cracking rig.
pub fn scenarios() -> [Scenario; 4] {
    [
        Scenario {
            name: "online, throttled (100 guesses/hour)",
            guesses_per_second: 100.0 / 3600.0,
        },
        Scenario {
            name: "online, unthrottled (10 guesses/sec)",
            guesses_per_second: 10.0,
        },
        Scenario {
            name: "offline, slow hash (10k guesses/sec)",
            guesses_per_second: 1.0e4,
        },
        Scenario {
            name: "offline, fast hash (10B guesses/sec)",
            guesses_per_second: 1.0e10,
        },
    ]
}

pub fn analyze(password: &str) -> Analysis {
    analyze_with_common_passwords(password, &HashSet::new())
}

/// Same as [`analyze`], but a password is also flagged as "commonly used"
/// if it matches an entry in `extra_common` (e.g. loaded from a wordlist
/// file), not just the small built-in list.
pub fn analyze_with_common_passwords(password: &str, extra_common: &HashSet<String>) -> Analysis {
    let chars: Vec<char> = password.chars().collect();
    let length = chars.len();

    if length == 0 {
        return Analysis {
            length: 0,
            pool_size: 0,
            entropy_bits: 0.0,
            notes: Vec::new(),
        };
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_other = false;

    for &c in &chars {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii() {
            has_symbol = true;
        } else {
            has_other = true;
        }
    }

    let mut pool = 0u32;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_other {
        // Unicode is effectively unbounded; 100 is a deliberately modest
        // stand-in so a non-ASCII password isn't scored as zero-entropy,
        // without pretending we've measured the real alphabet size.
        pool += 100;
    }

    let mut notes = Vec::new();
    let lower_password = password.to_lowercase();

    if COMMON_PASSWORDS.contains(&lower_password.as_str()) || extra_common.contains(&lower_password) {
        notes.push("matches a commonly used password".to_string());
        return Analysis {
            length,
            pool_size: pool,
            entropy_bits: 8.0, // log2(256): "one of a few hundred guesses everyone tries first"
            notes,
        };
    }

    // Cracking tools mangle every word in a dictionary through a small set of
    // substitution rules before trying it, so a password that only differs
    // from a common one by "@" for "a" or "0" for "o" is not meaningfully
    // safer. The normalized form is checked against the same lists as the
    // exact match above.
    let delooted = undo_leet_substitutions(&lower_password);
    if delooted != lower_password
        && (COMMON_PASSWORDS.contains(&delooted.as_str()) || extra_common.contains(&delooted))
    {
        notes.push("matches a commonly used password with leetspeak substitutions".to_string());
        return Analysis {
            length,
            pool_size: pool,
            entropy_bits: 8.0,
            notes,
        };
    }

    let repeat_run = longest_repeat_run(&chars);
    let seq_run = longest_sequential_run(&chars);
    let keyboard_run = longest_keyboard_run(&lower_password);

    let (worst_run, label) = [
        (repeat_run, "repeated character run"),
        (seq_run, "sequential run"),
        (keyboard_run, "keyboard-walk pattern"),
    ]
    .into_iter()
    .max_by_key(|(run, _)| *run)
    .unwrap();

    // A run of N characters that an attacker's tooling would generate as a
    // unit contributes roughly as much guessing effort as one character
    // outside the run, not N independent random characters. Rather than
    // model that precisely, just don't count the repeated part.
    let effective_len = if worst_run >= 3 {
        notes.push(format!("{} detected (length {})", label, worst_run));
        (length - (worst_run - 1)).max(1)
    } else {
        length
    };

    let entropy_bits = if pool > 0 {
        effective_len as f64 * (pool as f64).log2()
    } else {
        0.0
    };

    Analysis {
        length,
        pool_size: pool,
        entropy_bits,
        notes,
    }
}

/// Maps common leetspeak stand-ins back to the letter they're standing in
/// for. `1` and `!` are read as `i` (as in `adm1n`), not `l`, since that's
/// the more common usage; `|` is read as `l` instead, so the two don't
/// collide. This is a lossy, one-way normalization meant only to answer
/// "does this collapse to a known weak password", not to reverse leetspeak
/// in general.
fn undo_leet_substitutions(lower: &str) -> String {
    lower
        .chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '8' => 'b',
            '3' => 'e',
            '1' | '!' => 'i',
            '|' => 'l',
            '0' => 'o',
            '5' | '$' => 's',
            '7' | '+' => 't',
            other => other,
        })
        .collect()
}

fn longest_repeat_run(chars: &[char]) -> usize {
    if chars.is_empty() {
        return 0;
    }
    let mut run = 1usize;
    let mut best = 1usize;
    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run += 1;
        } else {
            run = 1;
        }
        best = best.max(run);
    }
    best
}

fn longest_sequential_run(chars: &[char]) -> usize {
    if chars.is_empty() {
        return 0;
    }
    let codes: Vec<i64> = chars.iter().map(|c| c.to_ascii_lowercase() as i64).collect();
    let mut asc = 1usize;
    let mut desc = 1usize;
    let mut best = 1usize;
    for i in 1..codes.len() {
        let diff = codes[i] - codes[i - 1];
        asc = if diff == 1 { asc + 1 } else { 1 };
        desc = if diff == -1 { desc + 1 } else { 1 };
        best = best.max(asc).max(desc);
    }
    best
}

fn longest_keyboard_run(lower_password: &str) -> usize {
    const ROWS: [&str; 6] = [
        "qwertyuiop",
        "poiuytrewq",
        "asdfghjkl",
        "lkjhgfdsa",
        "zxcvbnm",
        "mnbvcxz",
    ];
    let chars: Vec<char> = lower_password.chars().collect();
    let n = chars.len();
    let mut best = 0usize;
    for start in 0..n {
        for end in (start + 1)..=n {
            let len = end - start;
            if len < 3 {
                continue;
            }
            let substr: String = chars[start..end].iter().collect();
            if ROWS.iter().any(|row| row.contains(&substr)) {
                best = best.max(len);
            }
        }
    }
    best
}

/// Renders a duration in the coarsest unit that keeps the number readable.
pub fn format_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds > 1.0e15 {
        return "essentially forever".to_string();
    }

    const MINUTE: f64 = 60.0;
    const HOUR: f64 = MINUTE * 60.0;
    const DAY: f64 = HOUR * 24.0;
    const YEAR: f64 = DAY * 365.25;
    const CENTURY: f64 = YEAR * 100.0;

    if seconds < 1.0 {
        "less than a second".to_string()
    } else if seconds < MINUTE {
        format!("{:.0} seconds", seconds)
    } else if seconds < HOUR {
        format!("{:.1} minutes", seconds / MINUTE)
    } else if seconds < DAY {
        format!("{:.1} hours", seconds / HOUR)
    } else if seconds < YEAR {
        format!("{:.1} days", seconds / DAY)
    } else if seconds < CENTURY {
        format!("{:.1} years", seconds / YEAR)
    } else {
        format!("{:.1} centuries", seconds / CENTURY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case {
        name: &'static str,
        password: &'static str,
        min_bits: f64,
        max_bits: f64,
        note_contains: Option<&'static str>,
    }

    #[test]
    fn awkward_cases() {
        let cases = [
            Case {
                name: "empty password",
                password: "",
                min_bits: 0.0,
                max_bits: 0.0,
                note_contains: None,
            },
            Case {
                name: "single character",
                password: "a",
                min_bits: 4.5,
                max_bits: 4.8,
                note_contains: None,
            },
            Case {
                name: "long repeated character",
                password: "aaaaaaaaaa",
                min_bits: 4.5,
                max_bits: 4.8,
                note_contains: Some("repeated character run"),
            },
            Case {
                name: "ascending alphabet run",
                password: "abcdefgh",
                min_bits: 4.5,
                max_bits: 4.8,
                note_contains: Some("sequential run"),
            },
            Case {
                name: "ascending digit run",
                password: "12345678",
                min_bits: 3.0,
                max_bits: 3.5,
                note_contains: Some("sequential run"),
            },
            Case {
                name: "keyboard walk",
                password: "qwertyuiop",
                min_bits: 4.5,
                max_bits: 4.8,
                note_contains: Some("keyboard-walk pattern"),
            },
            Case {
                name: "common password",
                password: "password",
                min_bits: 8.0,
                max_bits: 8.0,
                note_contains: Some("commonly used password"),
            },
            Case {
                name: "common password, different case",
                password: "Password1",
                min_bits: 8.0,
                max_bits: 8.0,
                note_contains: Some("commonly used password"),
            },
            Case {
                name: "strong random-looking password",
                password: "xQ7!mK9$pL2#vR",
                min_bits: 88.0,
                max_bits: 95.0,
                note_contains: None,
            },
            Case {
                name: "unicode with a trailing digit run",
                password: "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}123",
                min_bits: 45.0,
                max_bits: 50.0,
                note_contains: Some("sequential run"),
            },
            Case {
                name: "whitespace only",
                password: "     ",
                min_bits: 4.8,
                max_bits: 5.2,
                note_contains: Some("repeated character run"),
            },
        ];

        for case in cases {
            let result = analyze(case.password);
            assert!(
                result.entropy_bits >= case.min_bits && result.entropy_bits <= case.max_bits,
                "{}: expected entropy in [{}, {}], got {}",
                case.name,
                case.min_bits,
                case.max_bits,
                result.entropy_bits
            );
            match case.note_contains {
                Some(fragment) => assert!(
                    result.notes.iter().any(|n| n.contains(fragment)),
                    "{}: expected a note containing '{}', got {:?}",
                    case.name,
                    fragment,
                    result.notes
                ),
                None => assert!(
                    result.notes.is_empty(),
                    "{}: expected no notes, got {:?}",
                    case.name,
                    result.notes
                ),
            }
        }
    }

    #[test]
    fn extra_wordlist_catches_passwords_the_builtin_list_misses() {
        let plain = analyze("correcthorsebatterystaple");
        assert!(plain.notes.is_empty());

        let mut wordlist = HashSet::new();
        wordlist.insert("correcthorsebatterystaple".to_string());
        let flagged = analyze_with_common_passwords("correcthorsebatterystaple", &wordlist);
        assert_eq!(flagged.entropy_bits, 8.0);
        assert!(flagged
            .notes
            .iter()
            .any(|n| n.contains("commonly used password")));

        // Matching is case-insensitive, same as the built-in list.
        let flagged_mixed_case =
            analyze_with_common_passwords("CorrectHorseBatteryStaple", &wordlist);
        assert_eq!(flagged_mixed_case.entropy_bits, 8.0);
    }

    #[test]
    fn leetspeak_substitutions_still_flag_as_common() {
        for password in ["p@ssw0rd", "l3tm3in", "adm1n", "W3lc0me"] {
            let result = analyze(password);
            assert_eq!(result.entropy_bits, 8.0, "{}: expected weak entropy", password);
            assert!(
                result
                    .notes
                    .iter()
                    .any(|n| n.contains("leetspeak substitutions")),
                "{}: expected a leetspeak note, got {:?}",
                password,
                result.notes
            );
        }
    }

    #[test]
    fn leetspeak_normalization_also_applies_to_wordlist_matches() {
        let mut wordlist = HashSet::new();
        wordlist.insert("correcthorsebatterystaple".to_string());
        let result =
            analyze_with_common_passwords("c0rrecth0rseb@ttery5tap|e", &wordlist);
        assert_eq!(result.entropy_bits, 8.0);
        assert!(result
            .notes
            .iter()
            .any(|n| n.contains("leetspeak substitutions")));
    }

    #[test]
    fn scenarios_all_have_positive_guess_rates() {
        for scenario in scenarios() {
            assert!(scenario.guesses_per_second > 0.0);
        }
    }

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(0.4), "less than a second");
        assert_eq!(format_duration(30.0), "30 seconds");
        assert!(format_duration(3600.0 * 5.0).contains("hours"));
        assert!(format_duration(3600.0 * 24.0 * 400.0).contains("years"));
    }
}
