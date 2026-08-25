# crackclock

A command-line tool that answers one question: how long would it take to
guess this password?

Most password strength meters on signup forms give you a colored bar and no
explanation. This gives you a number, in units of time, for a few different
attacker scenarios, along with the specific reason the number is small if it
is small.

## How it estimates

The estimate starts from character-class variety: does the password use
lowercase, uppercase, digits, symbols, or other Unicode characters, and how
long is it. That gives a naive entropy in bits, treating the password as if
it were drawn uniformly at random from that alphabet.

Then it checks for a few things real cracking tools try before anything
else, because a naive entropy estimate badly overstates the difficulty of
these:

- an exact match against a short list of extremely common passwords, or a
  match after undoing common leetspeak substitutions (`p@ssw0rd` ->
  `password`)
- a run of the same character repeated (`aaaaaaaa`)
- a sequential run of characters (`abcdefgh`, `12345678`)
- a keyboard walk (`qwertyuiop`)

When one of these is found, the entropy estimate is knocked down to
roughly what's left after removing the pattern, and the reason is reported
alongside the number.

The bit estimate is then converted into a guess count (`2^bits`) and divided
by an assumed guess rate for a handful of attack scenarios, from a throttled
login form up to an offline attack against a fast, unsalted hash.

## Usage

```
cargo run --release -- 'qwerty'
```

```
length: 6 characters
character pool: 26
estimated entropy: 8.0 bits
note: matches a commonly used password

estimated time to crack by brute force:
  online, throttled (100 guesses/hour)    2.6 hours
  online, unthrottled (10 guesses/sec)    26 seconds
  offline, slow hash (10k guesses/sec)    less than a second
  offline, fast hash (10B guesses/sec)    less than a second
```

If no password is given as an argument, it reads one line from stdin
instead:

```
echo 'Tr0ub4dor&3' | cargo run --release
```

Passwords containing spaces need to be passed as a single quoted argument,
or piped in on stdin - the CLI does not distinguish "one argument with
spaces" from "several words".

By default the common-password check only covers a short built-in list.
Pass `--wordlist` with a path to a file (one password per line) to also
flag matches against a larger corpus:

```
cargo run --release -- --wordlist rockyou.txt 'letmein123'
```

## Known limitations

- Input from stdin is not hidden from the terminal. This is a query tool
  for testing password ideas, not a login prompt; don't feed it a password
  you're actively using without expecting it to show up in your shell
  history or terminal scrollback.
- The built-in common-password list is short. Use `--wordlist` to check
  against a larger corpus instead.
- Pattern detection only looks at exact ASCII keyboard rows and simple
  ascending/descending runs. Leetspeak substitutions are undone before the
  common-password check, but a dictionary word with a digit appended
  (`password7`) or two words joined together isn't caught unless it happens
  to be in the common-password list or wordlist verbatim.
- The crack-time estimate is exhaustive-search time (the full keyspace),
  not expected time to find one specific password (which would typically
  be half that). This makes the numbers a bit pessimistic for an attacker
  and a bit optimistic for you.

## Building and testing

```
cargo build
cargo test
```

No third-party dependencies; standard library only.

## License

MIT, see [LICENSE](LICENSE).
