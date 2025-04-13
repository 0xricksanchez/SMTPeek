use colored::Colorize;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::cli::OutputFormat;
use crate::target::{TestResult, UserStatus};

#[derive(Clone, Debug)]
pub struct OutputHandler {
    pub format: OutputFormat,
    is_color: bool,
    live_mode: bool,
}

impl OutputHandler {
    pub fn new(format: OutputFormat, is_color: bool, live_mode: bool) -> Self {
        // Respect the user's choice for live mode console output (stderr)
        // Color setting primarily affects stderr now unless format is Standard
        if !is_color && format == OutputFormat::Standard {
            colored::control::set_override(false);
        } else {
            // Ensure color is enabled if requested or for non-standard formats where it's ignored anyway
            colored::control::set_override(true);
        }

        Self {
            format,
            is_color,
            live_mode,
        }
    }

    /// Prints the final test result.
    /// Behavior depends on format and `live_mode` flags set during initialization.
    /// - Standard Format + Live Mode: Prints SUCC/FAIL line to STDERR.
    /// - Standard Format + Not Live Mode: Prints final result line to STDOUT.
    /// - Json/Csv/Machine Format: Prints formatted line to STDOUT.
    pub fn print_result(&self, result: &TestResult) {
        match self.format {
            OutputFormat::Standard => {
                if self.live_mode {
                    // --- Print Live Result to STDERR ---
                    let (_status_str_dummy, prefix) = if self.is_color {
                        let prefix = match result.status {
                            UserStatus::Valid => "[SUCC]".green().bold(),
                            UserStatus::Invalid => "[FAIL]".red().bold(),
                            UserStatus::Unknown => "[????]".yellow().bold(),
                        };
                        ("", format!("{prefix}"))
                    } else {
                        let prefix = match result.status {
                            UserStatus::Valid => "[SUCC]",
                            UserStatus::Invalid => "[FAIL]",
                            UserStatus::Unknown => "[????]",
                        };
                        ("", prefix.to_string())
                    };

                    // Use helper for reason, respecting color flag
                    let server_response = self.format_server_response(&result.raw_response);

                    // Clear line on stderr using ANSI escape code
                    eprint!("\x1B[2K\r");
                    // Print live result format to stderr
                    eprintln!("{} {:<15} {}", prefix, result.username, server_response);
                    io::stderr().flush().unwrap(); // Ensure it appears
                } else {
                    // --- Print Final Result to STDOUT (non-live standard) ---
                    // This is typically used only if a final summary loop is added
                    // back for verbose mode, or if called outside the main worker loop.
                    let (status_str, prefix) = if self.is_color {
                        let status = match result.status {
                            UserStatus::Valid => "VALID".green().bold(),
                            UserStatus::Invalid => "INVALID".red(),
                            UserStatus::Unknown => "UNKNOWN".yellow(),
                        };
                        let prefix = "[+]".blue().bold();
                        (format!("{status}"), format!("{prefix}"))
                    } else {
                        let status = match result.status {
                            UserStatus::Valid => "VALID",
                            UserStatus::Invalid => "INVALID",
                            UserStatus::Unknown => "UNKNOWN",
                        };
                        let prefix = "[+]";
                        (status.to_string(), prefix.to_string())
                    };
                    let server_response = self.format_server_response(&result.raw_response);
                    println!(
                        "{} {:20} - {:<8} {}",
                        prefix, result.email, status_str, server_response
                    );
                }
            } // End OutputFormat::Standard

            OutputFormat::Json => {
                let json = serde_json::json!({
                    "username": result.username, "email": result.email,
                    "status": result.status.to_string(), "reason": result.reason,
                    "response_time_ms": result.response_time, "raw_response": result.raw_response
                });
                // Print JSON to stdout
                println!("{}", serde_json::to_string(&json).unwrap_or_default());
            }
            OutputFormat::Csv => {
                // Print CSV line to stdout (consider adding header externally before loop)
                println!(
                    "{},{},{},\"{}\",{},\"{}\"",
                    result.username,
                    result.email,
                    result.status,
                    result.reason.replace('"', "\"\""),
                    result.response_time,
                    result.raw_response.replace('"', "\"\"")
                );
            }
            OutputFormat::Machine => {
                // Print Machine line to stdout
                println!(
                    "STATUS:{}\tUSER:{}\tEMAIL:{}\tREASON:{}\tTIME:{}",
                    result.status,
                    result.username,
                    result.email,
                    result.reason,
                    result.response_time
                );
            }
        }
    }

    /// Formats the first line of the server response, optionally coloring status code.
    /// Respects the `is_color` flag.
    pub fn format_server_response(&self, raw_response: &str) -> String {
        if raw_response.is_empty() {
            return if self.is_color {
                "No server response".dimmed().to_string()
            } else {
                "No server response".to_string()
            };
        }
        let first_line = raw_response.lines().next().unwrap_or(raw_response);
        let status_code =
            if first_line.len() >= 3 && first_line.chars().take(3).all(|c| c.is_ascii_digit()) {
                &first_line[0..3]
            } else {
                ""
            };

        if status_code.is_empty() {
            first_line.trim().to_string() // Trim potential whitespace
        } else {
            let message = if first_line.len() > 4 {
                first_line[4..].trim()
            } else {
                ""
            };
            if self.is_color {
                let colored_code = match &status_code[0..1] {
                    "2" => status_code.green(),
                    "4" => status_code.yellow(),
                    "5" => status_code.red(),
                    _ => status_code.normal(),
                };
                format!("{colored_code} {message}")
            } else {
                format!("{status_code} {message}")
            }
        }
    }

    /// Prints live testing status (e.g., [*] TEST user...).
    pub fn print_live_status(
        &self,
        username: &str,
        email: &str,
        status: &str,
        test_string: Option<&str>,
    ) {
        //  Only print live status if format is Standard AND live mode is on
        if !self.live_mode || self.format != OutputFormat::Standard {
            return;
        }

        let status_display = if self.is_color {
            match status {
                "VALID" => "VALID".green().bold(),
                "TEST" | "Testing" => "TEST".yellow().bold(),
                _ => "INVALID".red().bold(),
            }
        } else {
            match status {
                "VALID" => "VALID".normal(),
                "TEST" | "Testing" => "TEST".normal(),
                _ => "INVALID".normal(),
            }
        };
        let prefix = if self.is_color {
            "[*]".blue()
        } else {
            "[*]".normal()
        };

        eprint!("\x1B[2K\r"); // Clear line on stderr
        if username == email {
            if let Some(test_str) = test_string {
                eprint!("{prefix} {status_display} {username:<20} VRFY {test_str}");
            } else {
                eprint!("{prefix} {status_display} {username:<20}");
            }
        } else {
            let domain = email.split('@').next_back().unwrap_or("");
            if let Some(test_str) = test_string {
                eprint!("{prefix} {status_display} {username} @ {domain} VRFY {test_str}");
            } else {
                eprint!("{prefix} {status_display} {username} @ {domain}");
            }
        }
        io::stderr().flush().unwrap(); // Ensure update appears
    }

    // Move to the next line (for live mode)
    pub fn next_line(&self) {
        if self.live_mode {
            print!("\r{}", " ".repeat(80)); // Clear current line
            println!(); // Move to next line
        }
    }

    // Print a banner
    pub fn print_banner(&self) {
        let version = env!("CARGO_PKG_VERSION");
        let authors = env!("CARGO_PKG_AUTHORS");
        let repo = env!("CARGO_PKG_REPOSITORY");

        if self.is_color {
            eprint!(
                "{}",
                r"
 ███████╗███╗   ███╗████████╗██████╗ ███████╗███████╗██╗  ██╗
 ██╔════╝████╗ ████║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██║ ██╔╝
 ███████╗██╔████╔██║   ██║   ██████╔╝█████╗  █████╗  █████╔╝
 ╚════██║██║╚██╔╝██║   ██║   ██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗
 ███████║██║ ╚═╝ ██║   ██║   ██║     ███████╗███████╗██║  ██╗
 ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
"
                .cyan()
                .bold()
            );
            // Print Name, Version, and Author below the art
            eprintln!(
                "                                     v{} - by {}",
                version.green().bold(),
                authors.green().bold(),
            );
            eprintln!(
                "                                     {}",
                "High-performance, concurrent SMTP user validation".dimmed()
            );
            eprintln!(
                "                                     <{}>",
                repo.dimmed().underline()
            );
        } else {
            // Non-is_color output - Use the correct name and version
            eprintln!("SMTPeek v{version} - by {authors}");
            eprintln!("High-performance, concurrent SMTP user validation <{repo}>");
        }
        eprintln!();
    }

    pub fn print_target_info(
        &self,
        target: &str,
        port: u16,
        mode: &str,
        user_count: usize,
        concurrency: usize,
        has_domains: bool,
        domain_count: usize,
    ) {
        let label_width = 15;
        let separator_len = label_width + 25;
        let separator = "-".repeat(separator_len).dimmed();

        // --- Header ---
        eprintln!("{separator}");
        let title = "Target Configuration";
        let centered_title = format!("{title:^separator_len$}");
        eprintln!("{}", centered_title.bold());
        eprintln!("{separator}");

        // --- Table Body (Optionally colorize target) ---
        let target_display = format!("{target}:{port}");
        eprintln!(
            "{:<width$}: {}",
            "Target",
            target_display.cyan(),
            width = label_width
        );
        eprintln!("{:<width$}: {}", "Mode", mode, width = label_width);
        eprintln!(
            "{:<width$}: {}",
            "Usernames",
            user_count,
            width = label_width
        );

        if has_domains {
            let total_tests = user_count * domain_count;
            eprintln!(
                "{:<width$}: {}",
                "Domains",
                domain_count,
                width = label_width
            );
            eprintln!(
                "{:<width$}: {} ({} users x {} domains)",
                "Total Tests",
                total_tests,
                user_count,
                domain_count,
                width = label_width
            );
        } else {
            eprintln!("{:<width$}: N/A (disabled)", "Domains", width = label_width);
            eprintln!(
                "{:<width$}: {} (no domain appending)",
                "Total Tests",
                user_count,
                width = label_width
            );
        }
        eprintln!(
            "{:<width$}: {}",
            "Concurrency",
            concurrency,
            width = label_width
        );

        // --- Footer ---
        eprintln!("{separator}");
        eprintln!();
    }

    // Print statistics
    pub fn print_statistics(
        &self,
        valid_count: usize,
        invalid_count: usize,
        unknown_count: usize,
        total: usize,
    ) {
        eprintln!(); // Add a preceding newline for spacing

        let separator = "-".repeat(60); // Adjust width as needed
        eprintln!("{}", separator.dimmed()); // Dimmed separator

        eprintln!(
            "{} {} {} | {} {} | {} {} | {} {}",
            "STATS".bold(),
            "Total:".bold(),
            total.to_string().bold(),
            "Valid:".green().bold(),
            valid_count.to_string().green().bold(),
            "Invalid:".red().bold(),
            invalid_count.to_string().red(),
            "Unknown:".yellow().bold(),
            unknown_count.to_string().yellow()
        );
        eprintln!("{}", separator.dimmed());
        eprintln!();
    }

    /// Prints summary of valid users found.
    pub fn print_valid_summary(&self, valid_results: &[TestResult]) {
        if self.format != OutputFormat::Standard {
            return;
        } // Only for standard console output

        if valid_results.is_empty() {
            return;
        }

        let separator = "-".repeat(60);
        let dimmed_separator = if self.is_color {
            separator.dimmed().to_string()
        } else {
            separator
        };

        eprintln!("\n{dimmed_separator}");
        let title = "Valid User Details:";
        eprintln!(
            "{}",
            if self.is_color {
                title.bold()
            } else {
                title.normal()
            }
        );
        eprintln!();

        for result in valid_results {
            let email_display = if self.is_color {
                result.email.green().bold().to_string()
            } else {
                result.email.clone()
            };
            let reason_display = self.format_server_response(&result.raw_response);
            eprintln!("  {email_display:<30} - {reason_display}"); // Print to stderr
        }
        eprintln!("{dimmed_separator}");
    }

    /// Prints connection status messages.
    pub fn print_connection_status(&self, host: &str, port: u16, status: &str, ok: bool) {
        if self.format != OutputFormat::Standard {
            return;
        } // Only for standard console output

        let indicator = if ok {
            if self.is_color {
                "[+]".green().bold()
            } else {
                "[+]".normal()
            }
        } else if self.is_color {
            "[>]".yellow().bold()
        } else {
            "[>]".normal()
        };
        if self.is_color {
            let status_display = if ok {
                status.green().bold()
            } else {
                status.yellow().bold()
            };
            eprintln!("{indicator} Connection to {host}:{port} - {status_display}",);
        } else {
            eprintln!("{indicator} Connection to {host}:{port} - {status}");
        }
    }

    // Save results to a file
    pub async fn save_results_to_file(
        &self,
        results: &[TestResult],
        path: &PathBuf,
    ) -> io::Result<()> {
        let mut file = File::create(path).await?;

        match self.format {
            OutputFormat::Json => {
                let json = serde_json::json!(results);
                file.write_all(serde_json::to_string_pretty(&json).unwrap().as_bytes())
                    .await?;
            }
            OutputFormat::Csv => {
                // Write CSV header
                file.write_all(b"username,email,status,reason,response_time_ms,raw_response\n")
                    .await?;

                // Write each result
                for result in results {
                    let line = format!(
                        "{},{},{},\"{}\",{},\"{}\"\n",
                        result.username,
                        result.email,
                        result.status,
                        result.reason.replace('"', "\"\""),
                        result.response_time,
                        result.raw_response.replace('"', "\"\"")
                    );
                    file.write_all(line.as_bytes()).await?;
                }
            }
            _ => {
                // For other formats, use a standard format
                for result in results {
                    let line =
                        format!("[{}] {} - {}\n", result.status, result.email, result.reason);
                    file.write_all(line.as_bytes()).await?;
                }
            }
        }

        Ok(())
    }
}
