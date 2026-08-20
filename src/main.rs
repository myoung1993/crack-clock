use std::env;
use std::io::{self, Read};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

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

    let analysis = crackclock::analyze(&password);

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
