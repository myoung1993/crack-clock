use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    let extra_common = match extract_wordlist_flag(&mut args) {
        Some(path) => load_wordlist(&path).unwrap_or_else(|err| {
            eprintln!("failed to read wordlist '{}': {}", path, err);
            process::exit(1);
        }),
        None => HashSet::new(),
    };

    let password = if args.is_empty() {
        eprintln!("reading password from stdin (input will be visible)");
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .expect("failed to read from stdin");
        input.trim_end_matches(['\n', '\r']).to_string()
    } else {
        args.join(" ")
    };

    let analysis = crackclock::analyze_with_common_passwords(&password, &extra_common);

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
