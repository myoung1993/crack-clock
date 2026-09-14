use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::process;

mod terminal;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    let extra_common = match extract_wordlist_flag(&mut args) {
        Some(path) => load_wordlist(&path).unwrap_or_else(|err| {
            eprintln!("failed to read wordlist '{}': {}", path, err);
            process::exit(1);
        }),
        None => HashSet::new(),
    };

    let json_output = extract_json_flag(&mut args);

    let password = if args.is_empty() {
        terminal::read_password().unwrap_or_else(|err| {
            eprintln!("failed to read password from stdin: {}", err);
            process::exit(1);
        })
    } else {
        args.join(" ")
    };

    let analysis = crackclock::analyze_with_common_passwords(&password, &extra_common);

    if json_output {
        println!("{}", analysis_to_json(&analysis));
        return;
    }

    println!("length: {} characters", analysis.length);
    println!("character pool: {}", analysis.pool_size);
    println!("estimated entropy: {:.1} bits", analysis.entropy_bits);

    if analysis.notes.is_empty() {
        println!("no obvious weaknesses detected");
    } else {
        for note in &analysis.notes {
            println!("note: {}", note);
        }
    }

    println!();
    println!("estimated time to crack by brute force:");
    for scenario in crackclock::scenarios() {
        let seconds = analysis.crack_time_seconds(scenario.guesses_per_second);
        println!(
            "  {:<40} {}",
            scenario.name,
            crackclock::format_duration(seconds)
        );
    }
}

/// Pulls the standalone `--json` flag out of `args` in place, returning
/// whether it was present.
fn extract_json_flag(args: &mut Vec<String>) -> bool {
    match args.iter().position(|a| a == "--json") {
        Some(pos) => {
            args.remove(pos);
            true
        }
        None => false,
    }
}

/// Renders an analysis as a single-line JSON object, for callers that want
/// to parse the result instead of scraping the human-readable report.
/// Written by hand rather than pulling in a JSON crate, since the shape is
/// fixed and small.
fn analysis_to_json(analysis: &crackclock::Analysis) -> String {
    let notes = analysis
        .notes
        .iter()
        .map(|n| format!("\"{}\"", json_escape(n)))
        .collect::<Vec<_>>()
        .join(",");

    let scenarios = crackclock::scenarios()
        .iter()
        .map(|scenario| {
            let seconds = analysis.crack_time_seconds(scenario.guesses_per_second);
            format!(
                "{{\"name\":\"{}\",\"guesses_per_second\":{},\"seconds\":{},\"human\":\"{}\"}}",
                json_escape(scenario.name),
                json_number(scenario.guesses_per_second),
                json_number(seconds),
                json_escape(&crackclock::format_duration(seconds))
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"length\":{},\"pool_size\":{},\"entropy_bits\":{},\"notes\":[{}],\"scenarios\":[{}]}}",
        analysis.length,
        analysis.pool_size,
        json_number(analysis.entropy_bits),
        notes,
        scenarios
    )
}

/// Formats an f64 for embedding in JSON. `Infinity` and `NaN` (possible for
/// crack-time seconds on an absurdly long input) have no JSON representation,
/// so they become `null` rather than producing invalid output.
fn json_number(x: f64) -> String {
    if x.is_finite() {
        format!("{}", x)
    } else {
        "null".to_string()
    }
}

/// Escapes a string for use inside a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Pulls `--wordlist <path>` out of `args` in place, returning the path if
/// present. Exits the process if the flag is given without a value, since
/// there's no sensible way to continue.
fn extract_wordlist_flag(args: &mut Vec<String>) -> Option<String> {
    let flag_pos = args.iter().position(|a| a == "--wordlist")?;
    args.remove(flag_pos);
    if flag_pos >= args.len() {
        eprintln!("--wordlist requires a file path argument");
        process::exit(1);
    }
    Some(args.remove(flag_pos))
}

/// Loads one password per line from `path`, lowercased to match the
/// case-insensitive comparison `analyze_with_common_passwords` does against
/// the built-in list. Blank lines are skipped; nothing else about the file
/// format is assumed, since wordlists in the wild vary in line endings and
/// trailing whitespace.
fn load_wordlist(path: &str) -> io::Result<HashSet<String>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_flag_removes_it_wherever_it_appears() {
        let mut args = vec!["--json".to_string(), "hunter2".to_string()];
        assert!(extract_json_flag(&mut args));
        assert_eq!(args, vec!["hunter2".to_string()]);

        let mut args = vec!["hunter2".to_string()];
        assert!(!extract_json_flag(&mut args));
        assert_eq!(args, vec!["hunter2".to_string()]);
    }

    #[test]
    fn json_escape_handles_quotes_backslashes_and_control_chars() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\u{1}b"), "a\\u0001b");
    }

    #[test]
    fn json_number_maps_non_finite_to_null() {
        assert_eq!(json_number(1.5), "1.5");
        assert_eq!(json_number(f64::INFINITY), "null");
        assert_eq!(json_number(f64::NAN), "null");
    }

    #[test]
    fn analysis_to_json_produces_well_formed_output() {
        let analysis = crackclock::analyze("qwerty");
        let json = analysis_to_json(&analysis);
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"length\":6"));
        assert!(json.contains("\"notes\":[\"matches a commonly used password\"]"));
        assert!(json.contains("\"scenarios\":["));
    }
}
