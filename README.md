<p align="center">
  <img src="img/logo.png" alt="SMTPeek Logo" width="300"/>
</p>

<h1 align="center">SMTPeek</h1>

<p align="center">
  <strong>A high-performance, concurrent SMTP user enumeration tool written in Rust.</strong>
  <br />
  Designed for security testing to efficiently discover valid email accounts on SMTP servers.
  <br />
  Includes multiple probing techniques and TLS support (STARTTLS & Implicit).
</p>

<p align="center">
  <img src="https://img.shields.io/crates/v/smtpeek" alt="Crates.io">
  <img src="https://img.shields.io/github/license/0xricksanchez/SMTPeek" alt="License">
</p>

---

## Key Features

- 🚀 **High Performance:** Built with Rust and Tokio for asynchronous, concurrent scanning.
- ⚙️ **Multiple Enumeration Modes:** Supports `RCPT TO`, `VRFY`, `EXPN`, and experimental `Timing`, `Combined`, and `Stealth` methods (`-m`). `Auto` mode intelligently selects the best method.
- 🔐 **TLS Support:** Handles Plaintext, STARTTLS (port 25/587), and Implicit TLS (port 465) connections (`-s`). Optional certificate verification skip (`--tls-skip-verify`).
- ⚡ **Concurrency Control:** Adjustable number of concurrent connections (`-c`) and connection pool size (`--pool-size`).
- ⏱️ **Timing Adjustments:** Configurable timeouts (`-t`), retries (`-r`), fixed delays (`--delay`), and experimental adaptive delays (`--adaptive-delay`).
- 🎨 **Flexible Output:**
  - Standard colorized console output (default).
  - JSON (`-f json`) for machine parsing.
  - CSV (`-f csv`) for spreadsheets.
  - Simple `Machine` format (`-f machine`).
  - Live mode (`-L`) for real-time results (disables progress bar).
  - Verbose mode (`-v`) for detailed connection/debugging info.
- 🎯 **Target Flexibility:** Handles single usernames, wordlists (`-u`), optional domain appending (`-d`), and target randomization (`--randomize`).
- 🕵️ **Server Fingerprinting:** Optional attempt to identify SMTP server software (`--fingerprint`).
- 🚦 **Graceful Shutdown:** Responds to `Ctrl+C` to stop cleanly.

---

## Installation

### Using Cargo

```bash
cargo install smtpeek
```

### From Source

```bash
git clone https://github.com/0xricksanchez/SMTPeek
cd SMTPeek
cargo build --release
# The binary will be in ./target/release/smtpeek
```

## Usage

```bash
smtpeek [OPTIONS] --user <USER_INPUT> <HOST> [PORT]
```

### Arguments:

- `<HOST>`: Target SMTP server hostname or IP address (required).
- `[PORT]`: Target SMTP server port (optional) [default: 25].

### Required Options:

- `-u, --user <USER_INPUT>`: Username string or path to a file containing usernames.

### Optional Options:

For a full list of options, run:

```bash
smtpeek --help
```

## Probing Mechanisms (-m)

SMTPeek employs several methods to determine if a username/email corresponds to a valid account. Servers respond differently and may disable certain commands, so choosing the right mode (or using Auto) is crucial.

- **Auto** (Default)
  - How: Intelligently selects the best available method based on the server's capabilities advertised in the `EHLO` response.
  - Order: Prefers `VRFY` > `EXPN` > `RCPT TO`.
  - Best For: General use when server capabilities are unknown.
- **Rcpt**
  - How: Uses the standard SMTP transaction flow: `MAIL FROM:<sender>` followed by `RCPT TO:<target_email>`. Resets (`RSET`) between checks on the same connection.
  - Interpretation: Relies on the server's response code to `RCPT TO`.
    - 250 / 251: Valid.
    - 550 / 551 / 553 / common rejection messages: Invalid.
    - 4xx (Temporary Errors): Unknown (may indicate rate limiting).
  - Notes: Most widely supported method.
- **Vrfy**
  - How: Uses the `VRFY <username_or_email>` command. Some servers check only the username part.
  - Interpretation:
    - 250 / 251: Valid.
    - 252 (Ambiguous): Treated as Valid (account likely exists).
    - 550 / 551 / 553: Invalid.
    - 50x (Command Errors): Unknown.
  - Notes: Often disabled or returns ambiguous responses for security.
- **Expn**
  - How: Uses the `EXPN <list_or_alias>` command. Primarily for mailing lists.
  - Interpretation:
    - 250: Valid.
    - 5xx: Invalid.
    - 50x (Command Errors): Unknown.
  - Notes: Very often disabled.
- **Timing** (Experimental)
  - How: Uses `RCPT TO` internally. Compares the response time for the target user against a baseline time for a known-invalid user.
  - Interpretation: If the target user's response time is significantly longer than the baseline (using internal heuristics), it's flagged as potentially Valid, even if the status code indicates invalid/unknown.
  - Notes: Highly sensitive to network conditions and server behavior. Prone to false positives/negatives. Use critically.
- **Combined** (Experimental)
  - How: Attempts `VRFY`, then `EXPN`, then `RCPT` sequentially.
  - Interpretation: Returns the result of the first method that yields a definitive Valid or Invalid status. If all are Unknown, the final status is Unknown.
  - Notes: Can be useful if unsure which command works, but less efficient. May trigger more alerts.
- **Stealth** (Experimental)
  - How: Attempts to mimic less aggressive behavior. Uses random delays, sends a partial VRFY (mostly ignored), uses a slightly randomized `MAIL FROM` for the `RCPT TO` check.
  - Interpretation: Relies primarily on the `RCPT TO` result.
  - Notes: Effectiveness varies greatly depending on server detection mechanisms.

## Examples

### Default Mode (Concurrent, Auto Method)

```bash
# Test users from list against example.com, use 5 connections
smtpeek -u users.txt -d example.com -c 5 example.com
```

Example output:

```bash
# [...] Banner and Config [...]

[>] Connection to example.com:25 - Establishing connection pool...
[>] Connection to example.com:25 - Validating initial pool connection...
[+] Connection to example.com:25 - Pool connection verified successfully

[!] Running with 5 concurrent connections. High concurrency on slow networks (e.g., VPN) or against rate-limited/slow servers may cause delays or appear unresponsive. Consider lowering concurrency (-c) if issues arise.

[+] validuser@example.com - VALID 250 2.1.5 Ok
  Processing... [=================>] 100/100 (0s) Processing completed

------------------------------------------------------------
STATS Total: 100 | Valid: 1 | Invalid: 99 | Unknown: 0
------------------------------------------------------------

------------------------------------------------------------
Valid User Details:

  validuser@example.com          - 250 2.1.5 Ok
------------------------------------------------------------
```

### Live Mode (Sequential for Small Lists)

```bash
# Test users, show results immediately (disables progress bar)
smtpeek -u users.txt -d example.com -L example.com
```

Example output:

```bash
# [...] Banner and Config [...]

[>] Connection to example.com:25 - Establishing connection pool...
[>] Connection to example.com:25 - Pool connection verified successfully

[INFO] Small list in live mode, forcing sequential processing (concurrency=1).

[FAIL] unknown@example.com 550 5.1.1 User unknown
[SUCC] validuser@example.com 250 2.1.5 Ok
# ... more results ...

# --- Results Summary --- (Only shown if live or verbose)
# [+] validuser@example.com        - VALID    250 2.1.5 Ok
# [+] unknown@example.com        - INVALID  550 5.1.1 User unknown
# --- End Summary ---

------------------------------------------------------------
STATS Total: 100 | Valid: 1 | Invalid: 99 | Unknown: 0
------------------------------------------------------------

------------------------------------------------------------
Valid User Details:

  validuser@example.com          - 250 2.1.5 Ok
------------------------------------------------------------
```

### Implicit TLS (Port 465) and JSON Output

```bash
# Test list via implicit TLS, save results to JSON (with disabled colors)
smtpeek -C -u users.txt -d example.com -s -p 465 -f json -o results.json secure.example.com
```

Example output:

```
[
  {
    "email": "valid@example.com",
    "raw_response": "250 2.1.5 Ok",
    "reason": "RCPT accepted",
    "response_time_ms": 150,
    "status": "Valid",
    "username": "valid"
  },
  {
    "email": "invalid@example.com",
    "raw_response": "550 5.1.1 User unknown",
    "reason": "RCPT rejected",
    "response_time_ms": 80,
    "status": "Invalid",
    "username": "invalid"
  }
]
```

## Improvements Over Legacy Implementations\*

- SMTPeek offers significant advantages compared to older, often script-based tools (like smtp-user-enum in Perl or Python):
- True Concurrency: Uses async Rust for massively parallel checks, far exceeding sequential script performance.
- Modern Networking: Robust handling of TCP, STARTTLS, Implicit TLS, and connection pooling.
- Advanced Techniques: Includes experimental timing and stealth modes beyond basic command checks.
- Compiled Performance: Native code execution eliminates interpreter overhead.
- Memory Efficiency: Rust's memory management avoids common pitfalls of script memory usage.
- Flexible Output: Built-in support for common formats like JSON and CSV.

* (Based on comparisons with common Perl/Python smtp-user-enum scripts: [1](https://github.com/pentestmonkey/smtp-user-enum), [2](https://github.com/cytopia/smtp-user-enum)

## Contributing

Contributions are welcome! Please feel free to submit issues, open pull requests, or suggest improvements.

### Future Enhancements & TODOs

While SMTPeek is already a capable tool, here are some areas for potential future improvement:

| Feature / TODO                                 | Description                                                                                                                                     | Usefulness       | Complexity       | Notes                                                                                                     |
| :--------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- | :--------------- | :--------------- | :-------------------------------------------------------------------------------------------------------- |
| **Certificate Verification Control**           | Implement the `--tls-verify` flag to allow choosing between skipping verification, using platform checks, or specifying a custom CA bundle.     | 💥 **Very High** | 🟡 **Medium**    | Essential security feature. Requires CLI flag, conditional logic in TLS setup. Custom CA adds complexity. |
| **Error Handling & Reporting**                 | Provide more specific error types/messages for different failures (DNS, TCP, TLS, SMTP commands). Map SMTP codes to user-friendly explanations. | ✨ **High**      | 🟡 **Medium**    | Improves usability significantly. Involves mapping errors, parsing responses. Can be done incrementally.  |
| **Documentation**                              | Expand examples, add `CONTRIBUTING.md`, document nuances of modes/options more deeply.                                                          | 💥 **Very High** | 🟢 **Low-Med**   | Crucial for users. Examples/basic explanations are Low, deep dives/CONTRIBUTING are Medium.               |
| **Evasion Techniques (Basic)**                 | Implement simple evasion tactics like randomized delays (jitter), randomized HELO/MAIL FROM values behind the `--evasion` flag.                 | 👍 **Medium**    | 🟡 **Medium**    | Useful for basic IDS/rate limits. Requires `rand` crate, conditional logic.                               |
| **Username Mangling/Generation**               | Add options to generate variations of usernames (e.g., `jsmith`, `john.smith`) from a base list or pattern.                                     | ✨ **High**      | 🟡 **Medium**    | Increases effectiveness significantly. Requires defining rules, generation logic, integration.            |
| **Configuration File**                         | Allow specifying common options via a configuration file (e.g., TOML, YAML) instead of only command-line flags.                                 | ✨ **High**      | 🟡 **Medium-Hi** | Very convenient for power users. Requires config crate, parsing, layering logic.                          |
| **Explicit Implicit TLS Flag**                 | Add clearer control for Implicit TLS (e.g., `--implicit-tls` or `--tls=implicit`), especially for non-standard ports.                           | 👍 **Medium**    | 🟢 **Low-Med**   | Improves clarity/correctness for non-standard ports. Requires CLI change, logic adjustment.               |
| **Connection Pool Validation (NOOP Tuning)**   | Make the NOOP check for reused connections configurable (enable/disable/timeout). Ensure pool permit logic is robust.                           | 👍 **Medium**    | 🟢 **Low**       | Makes pool more robust. Adding config flag is Low. More complex NOOP handling is Low-Med.                 |
| **Evasion Techniques (Advanced)**              | Implement more complex evasion like connection rotation (configurable lifespan/usage count) or sophisticated timing adjustments.                | ✨ **High**      | 🔴 **High**      | Harder to implement correctly and test effectiveness. Might require significant changes.                  |
| **IPv6 Literal TLS Handling**                  | Investigate and potentially warn or adjust SNI behavior when connecting via TLS directly to an IPv6 literal address.                            | 🤷 **Low-Med**   | 🟡 **Medium**    | Edge case correction. Requires IP detection, conditional SNI handling, potential `rustls` config.         |
| **Advanced Timing Analysis (`--mode Timing`)** | Significantly refine the `--mode Timing` heuristics with better statistics, baseline methods, and configurable thresholds.                      | 🤷 **Low-Med**   | 🔴 **High**      | Difficult to make reliable, prone to errors. Requires significant stats/heuristics work.                  |

## Security and Ethical Use

⚠️ Warning: This tool is intended for authorized security testing and educational purposes only.

- Obtain Explicit Permission: Never use this tool against systems you do not have explicit, written permission to test. Unauthorized scanning is illegal and unethical.
- Use Responsibly: Employ reasonable concurrency (-c) and delays (--delay) to avoid disrupting services. Start with low concurrency and increase cautiously.
- Comply with Laws: Adhere to all applicable local, state, national, and international laws regarding network scanning and computer security.
- Responsible Disclosure: If you find vulnerabilities, report them responsibly to the system owner through appropriate channels.

The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
