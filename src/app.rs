use colored::Colorize;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    io,
    time::{Duration, Instant},
};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{
    fs::File as TokioFile,
    io::{AsyncWriteExt, BufWriter},
    signal,
    sync::{Notify, Semaphore, mpsc},
    task::JoinHandle,
};

use crate::input::InputSource;
use crate::output::OutputHandler;
use crate::target::{TestResult, TestTarget, UserStatus, generate_test_targets, randomize_targets};
use crate::test_methods::TestMethods;
use crate::{cli::Cli, connection::SmtpConnection};
use crate::{cli::OutputFormat, connection::ConnectionPool};

pub struct App {
    cli: Cli,
    output_handler: OutputHandler,
    shutdown_signal: Arc<Notify>,
}

impl App {
    pub fn new(cli: Cli) -> Self {
        // Initialize output handler
        let output_handler = OutputHandler::new(cli.output, cli.is_color, cli.live);
        let shutdown_signal = Arc::new(Notify::new());

        Self {
            cli,
            output_handler,
            shutdown_signal,
        }
    }

    // Spawn a task dedicated to listening for the Ctrl+C signal
    fn spawn_signal_listener(&self) {
        let shutdown_signal = self.shutdown_signal.clone();

        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    eprintln!("\nCtrl+C received, signaling shutdown...");
                    // Signal received, notify all waiters
                    shutdown_signal.notify_waiters();
                }
                Err(err) => {
                    // This error is serious
                    eprintln!("FATAL: Unable to listen for shutdown signal: {err}");
                    // std::process::exit(1);
                }
            }
        });
    }

    // Main application execution
    pub async fn run(&self) -> std::io::Result<()> {
        self.spawn_signal_listener();

        if !self.cli.is_color {
            colored::control::set_override(false);
        }

        self.output_handler.print_banner();

        if self.cli.host.parse::<Ipv4Addr>().is_err() && self.cli.host.parse::<Ipv4Addr>().is_err()
        {
            println!(
                "{} Invalid IP address format for host {}",
                "[!]".bold().red(),
                self.cli.host.red().bold(),
            );
            std::process::exit(1);
        }

        let user_name_req = self.cli.user.clone();

        // --- Load Usernames (interruptible point) ---
        let usernames = tokio::select! {
            biased; // Check shutdown first
             () = self.shutdown_signal.notified() => {
                eprintln!("Shutdown signaled during username loading.");
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Operation cancelled"));
             }
             res = tokio::task::spawn_blocking(move || { // Use spawn_blocking for potentially blocking file I/O
                 let user_input = InputSource::new(&user_name_req);
                 user_input.load_values()
             }) => match res {
                 Ok(Ok(users)) => users,
                 Ok(Err(e)) => { eprintln!("Error loading usernames: {e}"); return Err(e); },
                 Err(e) => { eprintln!("Task panic during username loading: {e}"); return Err(std::io::Error::other("Username loading panicked")); }
             }
        };

        // --- Load Domains (interruptible point) ---
        let domains = if let Some(domain_input_path) = self.cli.domain.clone() {
            // Clone path
            tokio::select! {
                 biased;
                 () = self.shutdown_signal.notified() => {
                    eprintln!("Shutdown signaled during domain loading.");
                    return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Operation cancelled"));
                 }
                 res = tokio::task::spawn_blocking(move || { // Use spawn_blocking
                     let domain_source = InputSource::new(&domain_input_path);
                     match domain_source.load_values() {
                         Ok(mut domains) => {
                             // Ensure domains are properly formatted
                             domains = domains.iter().map(|d| {
                                 d.chars().next().map_or_else(|| d.clone(), |first_char| {
                                     if first_char == '@' { d[1..].to_string() } else { d.clone() }
                                 })
                             }).collect();
                             Ok(domains)
                         }
                         Err(e) => Err(e),
                     }
                 }) => match res {
                     Ok(Ok(d)) => d,
                     Ok(Err(e)) => { eprintln!("Error loading domains: {e}"); return Err(e); }
                     Err(e) => { eprintln!("Task panic during domain loading: {e}"); return Err(std::io::Error::other("Domain loading panicked")); }
                 }
            }
        } else {
            Vec::new()
        };

        // --- Generate and Prepare Targets ---
        let mut test_targets = generate_test_targets(&usernames, &domains);
        if self.cli.randomize {
            test_targets = randomize_targets(test_targets);
        }

        let helo_domain = self.cli.helo.as_ref().map_or_else(
            || {
                hostname::get().map_or_else(
                    |_| "smtp-enum-rs.local".to_string(),
                    |h| h.to_string_lossy().to_string(),
                )
            },
            std::clone::Clone::clone,
        );

        let effective_concurrency = self.get_effective_concurrency(&test_targets);

        // --- Print target information ---
        self.output_handler.print_target_info(
            &self.cli.host,
            self.cli.port,
            &format!("{:?}", self.cli.mode),
            usernames.len(),
            effective_concurrency,
            !domains.is_empty(),
            domains.len(),
        );

        if self.cli.port != 25 && !self.cli.tls {
            println!(
                "{} Non-standard port {} without TLS. Proceed with caution.",
                "[>]".bold().yellow(),
                self.cli.port.to_string().bold().yellow(),
            );
        }

        // --- Execute Main Logic with Shutdown Handling ---
        let shutdown_signal_clone = self.shutdown_signal.clone();
        let main_logic_future = async {
            if test_targets.len() == 1 {
                self.handle_single_target(
                    &test_targets[0],
                    &helo_domain,
                    self.shutdown_signal.clone(),
                )
                .await
            } else {
                self.handle_multiple_targets(
                    &test_targets,
                    &helo_domain,
                    self.shutdown_signal.clone(),
                    effective_concurrency,
                )
                .await
            }
        };

        let _execution_result = tokio::select! {
            biased; // Prioritize checking the shutdown signal
            () = shutdown_signal_clone.notified() => {
                eprintln!("Shutdown signal detected in main run loop, stopping execution.");
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Operation cancelled by user"));
            }
            result = main_logic_future => {
                // Main logic completed (successfully or with an error) before shutdown signal
                // Explicitly return the result obtained from the future
                return result;
            }
        };
    }

    // Determine effective concurrency based on input size
    fn get_effective_concurrency(&self, targets: &[TestTarget]) -> usize {
        // If we're in live mode with a small number of targets, use sequential processing
        if self.cli.live && targets.len() < 25 {
            return 1;
        }

        self.cli.concurrency.max(1)

        // Otherwise use normal concurrency rules
        //match targets.len() {
        //    1 => 1,                                  // Single target, use single thread
        //    2..=10 => 2,                             // Very small list, use minimal concurrency
        //    11..=100 => self.cli.concurrency.min(5), // Small list, limit concurrency
        //    _ => self.cli.concurrency,               // Normal case, use requested concurrency
        //}
    }

    // Handle testing a single target (optimized path)
    async fn handle_single_target(
        &self,
        target: &TestTarget,
        helo_domain: &str,
        shutdown_signal: Arc<Notify>, // Pass signal
    ) -> std::io::Result<()> {
        self.output_handler.print_connection_status(
            &self.cli.host,
            self.cli.port,
            "Connecting...",
            false,
        );
        // --- Connection attempt with shutdown check ---
        let mut conn = tokio::select! {
            biased;
            () = shutdown_signal.notified() => {
                eprintln!("Shutdown during single target connection.");
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Cancelled"));
            }
            conn_result = SmtpConnection::new(
            &self.cli.host,
            self.cli.port,
            self.cli.timeout,
            helo_domain,
            self.cli.fingerprint,
            self.cli.tls,
            self.cli.tls_verify,
            1, // Connection ID for single use,
            self.cli.verbose
        ) => {
                 match conn_result {
                    Ok(conn) => {
                        self.output_handler.print_connection_status(&self.cli.host, self.cli.port, "Connected successfully", true);
                        conn
                    }
                    Err(e) => {
                        self.output_handler.print_connection_status(&self.cli.host, self.cli.port, &format!("Connection failed: {e}"), false);
                        return Err(e);
                    }
                }
            }
        };

        if self.cli.verbose {
            println!("Connected to SMTP server:");
            println!("  Banner: {}", conn.server_info.banner);
            println!("  Capabilities:");
            for cap in &conn.server_info.capabilities {
                println!("    {cap}");
            }
            if let Some(server_type) = &conn.server_info.server_type {
                println!("  Server type: {server_type}");
            }
            println!();
        }

        // Update live status if enabled - just show "TEST" status
        if self.cli.live {
            self.output_handler
                .print_live_status(&target.username, &target.email, "TEST", None);
        }

        // --- Test attempt with shutdown check ---
        let test_logic_future = TestMethods::test_user(
            &mut conn,
            target,
            &self.cli.mode,
            &self.cli.from_mail,
            self.cli.wrap,
            self.cli.timeout,
            self.cli.retry,
            &self.output_handler,
        );

        let start_time = Instant::now();
        let (status, reason, raw_response) = tokio::select! {
             biased;
             () = shutdown_signal.notified() => {
                 eprintln!("Shutdown during single target test.");
                 // Close connection before returning error
                 let _ = conn.close().await; // Best effort close
                 return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Cancelled"));
             }
             test_result = test_logic_future => test_result, // Returns tuple (status, reason, raw_response)
        };

        // --- Process Result ---
        let result = TestResult {
            username: target.username.clone(),
            email: target.email.clone(),
            status: status.clone(),
            reason,
            response_time: start_time.elapsed().as_millis(),
            raw_response,
        };

        // If in live mode, update the status with the correct validity
        if self.cli.live {
            self.output_handler.print_live_status(
                &target.username,
                &target.email,
                &status.to_string(),
                None, // No test string needed for final status
            );
            self.output_handler.next_line();
        }

        // --- Print result ---
        self.output_handler.print_result(&result);

        // Save results (check shutdown before potentially slow file I/O?) - less critical maybe
        if let Some(output_file) = &self.cli.output_file {
            // Consider adding select! here too if saving can be very slow
            match self
                .output_handler
                .save_results_to_file(&[result.clone()], output_file)
                .await
            {
                Ok(()) => println!("Result saved to {}", output_file.display()),
                Err(e) => eprintln!("Error saving result to file: {e}"),
            }
        }

        let _ = conn.close().await;
        Ok(())
    }

    /// Handles testing multiple targets concurrently with graceful shutdown.
    async fn handle_multiple_targets(
        &self,
        targets: &[TestTarget],
        helo_domain: &str, // Still needed for pool creation if not stored elsewhere
        shutdown_signal: Arc<Notify>, // Pass the shutdown signal Arc
        effective_concurrency: usize, // Pass calculated concurrencyhandle_mu
    ) -> io::Result<()> {
        // Show initial status message via the output handler
        self.output_handler.print_connection_status(
            &self.cli.host,
            self.cli.port,
            "Establishing connection pool...",
            false,
        );

        // Create the connection pool wrapped in an Arc and Mutex for thread safety
        let pool = Arc::new(tokio::sync::Mutex::new(ConnectionPool::new(
            self.cli.host.clone(),
            self.cli.port,
            helo_domain.to_string(), // Use passed helo_domain
            self.cli.timeout,
            self.cli.fingerprint,
            self.cli.tls,
            self.cli.tls_verify, // Pass tls_verify flag
            self.cli.pool_size,
            self.cli.verbose,
        )));

        // --- Initial Connection Check (Optional, with shutdown) ---
        if self.cli.skip_pool_check {
            eprintln!(
                "{} Skipping initial pool connection check",
                "[!]".bold().red()
            );
        } else {
            self.output_handler.print_connection_status(
                &self.cli.host,
                self.cli.port,
                "Validating initial pool connection...",
                false,
            );
            tokio::select! {
                 biased;
                 () = shutdown_signal.notified() => {
                     eprintln!("Shutdown signaled during initial pool connection check.");
                     return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled during initial connection"));
                 }
                 res = async {
                     let mut pool_guard = pool.lock().await;
                     let initial_conn_result = pool_guard.get_connection().await;
                     match initial_conn_result {
                        Ok(conn) => {
                            pool_guard.return_connection(conn);
                            drop(pool_guard); // Explicitly drop guard before printing status
                            self.output_handler.print_connection_status(
                                &self.cli.host, self.cli.port, "Pool connection verified successfully", true,
                            );
                            Ok::<(), io::Error>(())
                        }
                        Err(e) => {
                            drop(pool_guard); // Explicitly drop guard before printing status
                            self.output_handler.print_connection_status(
                                &self.cli.host, self.cli.port, &format!("Warning: Initial pool connection failed: {e}"), false,
                            );
                            eprintln!("Warning: Initial connection attempt failed: {e}. Will retry during testing...");
                            Ok::<(), io::Error>(()) // Continue anyway
                        }
                    }
                 } => res?,
            };
        }

        let sequential_live_mode = self.cli.live && effective_concurrency == 1;

        // Print concurrency info (moved from get_effective_concurrency for better placement)
        if effective_concurrency > 1 && !self.cli.live && !self.cli.verbose {
            eprintln!(
                "{} Running with {} concurrent connections. High concurrency on slow networks (e.g., VPN) or against rate-limited/slow servers may cause delays or appear unresponsive. Consider lowering concurrency (-c) if issues arise.",
                "[!]".red().bold(),
                effective_concurrency.to_string().yellow().bold()
            );
        }

        // --- Setup for Incremental File Writing ---
        let mut writer_handle: Option<JoinHandle<io::Result<()>>> = None;
        let output_tx: Option<mpsc::Sender<TestResult>> = if let Some(output_path) =
            self.cli.output_file.clone()
        {
            let (tx, mut rx) = mpsc::channel::<TestResult>(100);
            let requested_format = self.cli.output;

            let handle = tokio::spawn(async move {
                let file = TokioFile::create(&output_path).await?;
                let mut writer = BufWriter::new(file);

                // Write CSV header if needed
                if requested_format == OutputFormat::Csv {
                    writer
                        .write_all(b"username,email,status,reason,response_time_ms,raw_response\n")
                        .await?;
                }

                // Receive results and write them formatted
                while let Some(result) = rx.recv().await {
                    let line = match requested_format {
                        OutputFormat::Json => {
                            serde_json::to_string(&result).unwrap_or_default() + "\n"
                        }
                        OutputFormat::Csv => {
                            format!(
                                "{},{},{},\"{}\",{},\"{}\"\n",
                                result.username,
                                result.email,
                                result.status,
                                result.reason.replace('"', "\"\""),
                                result.response_time,
                                result.raw_response.replace('"', "\"\"")
                            )
                        }
                        OutputFormat::Machine => {
                            format!(
                                "STATUS:{}\tUSER:{}\tEMAIL:{}\tREASON:{}\tTIME:{}\n",
                                result.status,
                                result.username,
                                result.email,
                                result.reason,
                                result.response_time
                            )
                        }
                        OutputFormat::Standard => {
                            // Fallback format for file if Standard was chosen
                            format!("[{}] {} - {}\n", result.status, result.email, result.reason)
                        }
                    };
                    writer.write_all(line.as_bytes()).await?;
                }
                // Flush the buffer when the channel is closed
                writer.flush().await?;
                Ok(())
            });
            writer_handle = Some(handle);
            Some(tx)
        } else {
            None // No output file
        };

        // Setup progress bar (only if not live and not verbose)
        let progress_bar = if self.output_handler.format == OutputFormat::Standard
            && !self.cli.live
            && !self.cli.verbose
        {
            let pb = ProgressBar::new(targets.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .expect("Failed to create progress bar template")
                    .progress_chars("#>-"),
            );
            Some(Arc::new(pb))
        } else {
            None
        };
        let progress_bar_clone = progress_bar.clone();

        // --- Add initialization message (to stderr if standard) ---
        if self.output_handler.format == OutputFormat::Standard
            && !self.cli.live
            && !self.cli.verbose
            && effective_concurrency > 0
        {
            eprintln!(
                "{}",
                format!(
                    "[>] Initializing worker connections (up to {effective_concurrency})..."
                )
                .dimmed()
            );
        }
        eprintln!();

        // --- Setup Semaphore & Output Handler Arc ---
        let semaphore = Arc::new(Semaphore::new(effective_concurrency));
        let output_handler_arc = Arc::new(self.output_handler.clone());


        // --- Define the Stream Processing Future ---
        let stream_processing_future = async {
            // Clone data needed within this outer async block
            let from_mail = self.cli.from_mail.clone();
            let wrap = self.cli.wrap;
            let timeout = self.cli.timeout;
            let retry = self.cli.retry;
            let live_mode = self.cli.live;
            let verbose = self.cli.verbose;
            let output_format = self.cli.output;
            let is_color = self.cli.is_color;
            let mode = self.cli.mode;
            let delay = self.cli.delay;
            let adaptive_delay = self.cli.adaptive_delay;

            let target_stream = stream::iter(targets.iter().cloned())
            .map(|target| {
                // Clone Arcs and necessary data for the inner async block
                let semaphore = Arc::clone(&semaphore);
                let pool = Arc::clone(&pool);
                let shutdown_signal_task = shutdown_signal.clone();
                let progress_bar_task = progress_bar_clone.clone();
                let output_handler_task = output_handler_arc.clone();
                let from_mail_task = from_mail.clone();
                let worker_output_tx = output_tx.clone(); 

                // The core async block executed concurrently for each target
                async move {
                    // --- Acquire Semaphore Permit FIRST (with shutdown check) ---
                    let permit_result = tokio::select! {
                         biased;
                         () = shutdown_signal_task.notified() => Err("Shutdown"),
                         res = semaphore.acquire() => res.map_or_else(|_| Err("Semaphore closed"), Ok)
                    };
                    let _permit = match permit_result {
                        Ok(p) => p,
                        Err(reason) => {
                        return TestResult {
                            username: target.username.clone(),
                            email: target.email.clone(),
                            status: UserStatus::Unknown, // Set status
                            reason: format!("Task aborted ({reason}) before execution"),
                            response_time: 0,
                            raw_response: String::new(),
                        };

                        }
                    };

                    // --- Get Connection (Minimal Lock Scope) ---
                    let conn_result = { // Lock only for getting/creating the connection
                        let mut pool_guard = pool.lock().await;
                        pool_guard.get_connection().await // Might block on IO if creating new
                    };

                    let start_time = Instant::now(); // Start timing after getting conn attempt
                    #[allow(unused_assignments)]
                    let mut test_result_final: Option<TestResult> = None;

                    // --- Perform Test OUTSIDE the get_connection lock ---
                    match conn_result {
                        Ok(mut conn) => { // Got a connection
                            let test_future = TestMethods::test_user(
                                &mut conn, &target, &mode, &from_mail_task,
                                wrap, timeout, retry, &output_handler_task,
                            );
                            // Race test against shutdown
                            let test_outcome = tokio::select! {
                                biased;
                                () = shutdown_signal_task.notified() => None, // Shutdown during test
                                outcome = test_future => Some(outcome), // Test completed
                            };

                            // Store the result before returning connection
                            let result_before_return = match test_outcome {
                                Some((status, reason, raw_response)) => TestResult {
                                     username: target.username.clone(), email: target.email.clone(),
                                     status, reason, raw_response,
                                     response_time: start_time.elapsed().as_millis(),
                                },
                                None => {
                                    TestResult {
                                        username: target.username.clone(),
                                        email: target.email.clone(),
                                        status: UserStatus::Unknown,
                                        reason: "Test aborted by user signal".to_string(),
                                        response_time: start_time.elapsed().as_millis(),
                                        raw_response: String::new(),
                                    }
                                },
                            };
                            test_result_final = Some(result_before_return);

                            // Return connection (Brief Lock Scope)
                            pool.lock().await.return_connection(conn); // <- Lock acquired & released here
                        }
                        Err(e) => { // Failed to get connection initially
                                //
                                                         test_result_final = Some(TestResult {
                            username: target.username.clone(),
                            email: target.email.clone(),
                            status: UserStatus::Unknown,
                            reason: format!("Connection error: {e}"),
                            response_time: start_time.elapsed().as_millis(),
                            raw_response: String::new(),
                        });
                            // TODO: Update response time for the failed attempt??
                            // test_result_final.as_mut().unwrap().response_time = start_time.elapsed().as_millis();
                        }
                    }

                    // We should always have a result by now
                    let result = test_result_final.expect("[handle_multiple_targets]: test_result_final should be Some");
                   if let Some(ref sender) = worker_output_tx {
                         if sender.send(result.clone()).await.is_err() && verbose { eprintln!("[Worker {:?}] Failed to send result to writer task (channel closed).", _permit.forget()); }
                    }

                    // --- Process Output & Progress ---
                    // Determine if the result should be printed to the console immediately by this worker
                    let print_to_console_now = match output_format {
                        OutputFormat::Standard => live_mode || verbose, // Standard: Print if live OR verbose
                        _ => true, // Non-Standard (JSON/CSV/Machine): Always print immediately to stdout
                    };

                    // Print to console if needed (handles all console output cases within the worker)
                    if print_to_console_now {
                        // This single call correctly handles:
                        // - Standard format + Live Mode (prints SUCC/FAIL line to stderr)
                        // - Standard format + Verbose Mode (prints full line, though summary loop might repeat)
                        // - Non-Standard formats (prints JSON/CSV/Machine line to stdout)
                        output_handler_task.print_result(&result);
                    }

                    // --- Process Output/Progress based on format ---
                    if output_format == OutputFormat::Standard && !live_mode {
                             if let Some(pb) = &progress_bar_task {
                                 // Progress bar active
                                 if result.status == UserStatus::Valid {
                                     // Print valid results above the bar to stderr
                                     let reason_part = output_handler_task.format_server_response(&result.raw_response);
                                     let formatted_output = if is_color {
                                         format!("{} {} - {} {}", "[+]".green().bold(), result.email.green().bold(), "VALID".green().bold(), reason_part)
                                     } else {
                                         format!("[+] {} - VALID {}", result.email, reason_part)
                                     };
                                     pb.println(formatted_output); // Goes to stderr
                                 }
                                 pb.inc(1); // Increment progress bar
                            }
                            // NOTE: If verbose is also true here, the final summary loop might print again.
                            // If verbose is false, only valid users were printed above.
                    }

                    // --- Delay ---
                    if delay > 0 {
                        let calculated_delay = if adaptive_delay {
                            Duration::from_millis((result.response_time as f64 * 1.5) as u64)
                                .max(Duration::from_millis(10)) // Example minimum adaptive delay
                        } else {
                            Duration::from_millis(delay) // Fixed delay
                        };

                        tokio::select! {
                            biased;
                            () = shutdown_signal_task.notified() => { /* Shutdown during delay, just continue */ },
                            () = tokio::time::sleep(calculated_delay) => { /* Sleep finished */ },
                        };
                    }

                    result
                }
            })
            .buffer_unordered(effective_concurrency);

            target_stream.collect::<Vec<TestResult>>().await
        };

        // --- Execute the Stream Processing (with overall shutdown check) ---
        let results: Vec<TestResult>;
        tokio::select! {
            biased;
            () = shutdown_signal.notified() => {
                eprintln!("\nShutdown signaled, stopping concurrent processing...");
                results = Vec::new(); // Aborted, results are incomplete
            }
            collected_results = stream_processing_future => {
                results = collected_results;
                 // Only print this if progress bar wasn't used
                 if progress_bar.is_none() && !self.cli.live {
                     println!("Finished processing all targets.");
                 }
            }
        }

        // --- Process Final Results (runs after select! completes) ---
        if let Some(pb_arc) = progress_bar {
            if !pb_arc.is_finished() {
                pb_arc.finish_and_clear();
            }
        }

        // Count results from the collected vector (might be partial if shutdown occurred)
        let mut valid_count = 0;
        let mut invalid_count = 0;
        let mut unknown_count = 0;
        for result in &results {
            match result.status {
                UserStatus::Valid => valid_count += 1,
                UserStatus::Invalid => invalid_count += 1,
                UserStatus::Unknown => unknown_count += 1, // Aborted tasks count as Unknown
            }
        }

        // Sort the collected results for consistent output
        let mut sorted_results = results;
        sorted_results.sort_by(|a, b| {
            let a_priority = match a.status {
                UserStatus::Valid => 0,
                UserStatus::Unknown => 1,
                UserStatus::Invalid => 2,
            };
            let b_priority = match b.status {
                UserStatus::Valid => 0,
                UserStatus::Unknown => 1,
                UserStatus::Invalid => 2,
            };
            a_priority
                .cmp(&b_priority)
                .then_with(|| a.email.cmp(&b.email))
        });

        if !sequential_live_mode && self.cli.verbose && !self.cli.live && !sorted_results.is_empty()
        {
            println!("\n--- Results Summary ---");
            for result in &sorted_results {
                self.output_handler.print_result(result);
            }
            println!("--- End Summary ---");
        }

        self.output_handler.print_statistics(
            valid_count,
            invalid_count,
            unknown_count,
            sorted_results.len(),
        );

        let valid_only: Vec<TestResult> = sorted_results
            .iter()
            .filter(|r| r.status == UserStatus::Valid)
            .cloned()
            .collect();
        self.output_handler.print_valid_summary(&valid_only);

        if let Some(handle) = writer_handle {
             // Print status message to stderr
             if self.output_handler.format == OutputFormat::Standard { // Only print status if console output is standard
                 eprintln!("{}", "[>] Waiting for file writer to finish...".dimmed());
             }
             // Await the writer task and handle its result
             match handle.await {
                 Ok(Ok(())) => {
                      // Writer task finished successfully
                      if let Some(output_path) = &self.cli.output_file {
                         // Print confirmation to stderr
                         eprintln!("{} Results saved to {}", "[+]".green().bold(), output_path.display().to_string().bold());
                      }
                 }
                 Ok(Err(e)) => {
                     // Writer task completed but reported an IO error
                     eprintln!("{} Error writing results to file: {}", "[-]".red().bold(), e);
                 }
                 Err(e) => {
                      // Writer task panicked
                      eprintln!("{} File writer task panicked: {}", "[-]".red().bold(), e);
                 }
             }
        }

        Ok(())
    }
}
