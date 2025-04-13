use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::{
    cli::EnumMode,
    connection::{SmtpConnection, response_analysis},
};
use crate::{
    output::OutputHandler,
    target::{TestTarget, UserStatus},
};

// Implements test methods for SMTP user enumeration
pub struct TestMethods;

impl TestMethods {
    // Test a user with VRFY command
    pub async fn test_with_vrfy(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        timeout_secs: u64,
        retry_count: u8,
        output_handler: &OutputHandler,
    ) -> (UserStatus, String, String) {
        let mut last_error = String::new();
        let mut raw_response = String::new();

        // For VRFY, we might want to use just the username part without domain
        let test_string = if matches!(mode, &EnumMode::Vrfy) && target.has_domain {
            &target.username
        } else {
            &target.email
        };

        // Apply wrapping if requested
        let formatted_test_string = if wrap {
            format!("<{test_string}>")
        } else {
            test_string.to_string()
        };

        // Update live status with the test string
        output_handler.print_live_status(
            &target.username,
            &target.email,
            "TEST",
            Some(&formatted_test_string),
        );

        for _attempt in 0..retry_count {
            let cmd = format!("VRFY {formatted_test_string}");

            match conn.send_command(&cmd, timeout_secs).await {
                Ok(response) => {
                    raw_response.clone_from(&response);

                    // Analyze the response
                    if response_analysis::is_valid_user(&response) {
                        // 250 indicates a valid user
                        return (UserStatus::Valid, "VRFY accepted".to_string(), response);
                    } else if response_analysis::is_invalid_user(&response) {
                        // These codes/phrases typically indicate invalid users
                        return (UserStatus::Invalid, "VRFY rejected".to_string(), response);
                    } else if response_analysis::is_ambiguous(&response) {
                        // Server cannot verify but user might exist
                        // For consistency, treat ambiguous as Valid in VRFY mode
                        // Many SMTP servers are configured to not divulge if a user exists
                        if response.contains("252") {
                            return (
                                UserStatus::Valid,
                                "VRFY ambiguous (likely valid)".to_string(),
                                response,
                            );
                        }
                        return (UserStatus::Unknown, "VRFY ambiguous".to_string(), response);
                    } else if response_analysis::is_permanent_error(&response) {
                        // Other 5xx errors are usually permanent failures
                        last_error = response;
                        break;
                    }
                    // Other responses might be temporary
                    last_error = response;
                    // Continue to retry
                }
                Err(e) => {
                    last_error = format!("Command error: {e}");
                    // Small delay before retry
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // If we reach here, all attempts failed
        (
            UserStatus::Unknown,
            format!("VRFY failed: {last_error}"),
            raw_response,
        )
    }

    // Test a user with EXPN command
    pub async fn test_with_expn(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        timeout_secs: u64,
        retry_count: u8,
    ) -> (UserStatus, String, String) {
        let mut last_error = String::new();
        let mut raw_response = String::new();

        // Get the properly formatted email for the test
        let email = target.get_formatted_email(*mode, wrap);

        for _attempt in 0..retry_count {
            let cmd = format!("EXPN {email}");

            match conn.send_command(&cmd, timeout_secs).await {
                Ok(response) => {
                    raw_response.clone_from(&response);

                    // Analyze the response
                    if response_analysis::is_valid_user(&response) {
                        // 250 indicates a valid mailing list or user
                        return (UserStatus::Valid, "EXPN accepted".to_string(), response);
                    } else if response_analysis::is_invalid_user(&response) {
                        // These codes typically indicate invalid users
                        return (UserStatus::Invalid, "EXPN rejected".to_string(), response);
                    } else if response_analysis::is_ambiguous(&response) {
                        // Server cannot expand but address might exist
                        return (UserStatus::Unknown, "EXPN ambiguous".to_string(), response);
                    } else if response_analysis::is_permanent_error(&response) {
                        // Other 5xx errors are usually permanent failures
                        last_error = response;
                        break;
                    }
                    // Other responses might be temporary
                    last_error = response;
                    // Continue to retry
                }
                Err(e) => {
                    last_error = format!("Command error: {e}");
                    // Small delay before retry
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // If we reach here, all attempts failed
        (
            UserStatus::Unknown,
            format!("EXPN failed: {last_error}"),
            raw_response,
        )
    }

    // Test a user with RCPT TO command
    pub async fn test_with_rcpt(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        from_mail: &str,
        timeout_secs: u64,
        retry_count: u8,
    ) -> (UserStatus, String, String) {
        let mut last_error = String::new();
        let mut raw_response = String::new();

        // Get the properly formatted email for the test
        let email = target.get_formatted_email(*mode, wrap);

        for _attempt in 0..retry_count {
            // First send MAIL FROM
            let mail_cmd = format!("MAIL FROM:<{from_mail}>");

            match conn.send_command(&mail_cmd, timeout_secs).await {
                Ok(response) => {
                    if !response_analysis::is_success(&response) {
                        last_error = format!("MAIL FROM failed: {response}");
                        // If MAIL FROM fails, need to reset or reconnect
                        let _ = conn.send_command("RSET", timeout_secs).await;

                        // If it's a permanent error, break the retry loop
                        if response_analysis::is_permanent_error(&response) {
                            break;
                        }

                        // Temporary error, wait and continue
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }

                    // Then send RCPT TO
                    let rcpt_cmd = format!("RCPT TO:{email}");

                    match conn.send_command(&rcpt_cmd, timeout_secs).await {
                        Ok(rcpt_response) => {
                            raw_response.clone_from(&rcpt_response);

                            // Reset session for next attempt
                            let _ = conn.send_command("RSET", timeout_secs).await;

                            // Analyze the response
                            if response_analysis::is_valid_user(&rcpt_response) {
                                // These codes indicate valid recipient
                                return (
                                    UserStatus::Valid,
                                    "RCPT accepted".to_string(),
                                    rcpt_response,
                                );
                            } else if response_analysis::is_invalid_user(&rcpt_response) {
                                // These codes/phrases typically indicate invalid recipients
                                return (
                                    UserStatus::Invalid,
                                    "RCPT rejected".to_string(),
                                    rcpt_response,
                                );
                            } else if response_analysis::is_temporary_error(&rcpt_response) {
                                // Temporary failures, might be rate limiting
                                last_error = rcpt_response;
                                // Longer delay before retry
                                sleep(Duration::from_secs(1)).await;
                            } else {
                                // Other responses
                                last_error = rcpt_response;
                                // Continue to retry
                            }
                        }
                        Err(e) => {
                            last_error = format!("RCPT TO error: {e}");
                            // Reset session
                            let _ = conn.send_command("RSET", timeout_secs).await;
                            // Small delay before retry
                            sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
                Err(e) => {
                    last_error = format!("MAIL FROM error: {e}");
                    // Small delay before retry
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // If we reach here, all attempts failed
        (
            UserStatus::Unknown,
            format!("RCPT failed: {last_error}"),
            raw_response,
        )
    }

    // Test a user with timing-based detection
    pub async fn test_with_timing(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        from_mail: &str,
        timeout_secs: u64,
        retry_count: u8,
    ) -> (UserStatus, String, String) {
        // This is an advanced technique that looks for timing differences in responses
        // between valid and invalid users

        // First establish a baseline with an obviously invalid user
        let _invalid_email = "this.user.definitely.does.not.exist@example.com";
        let invalid_target = TestTarget::new_with_domain(
            "this.user.definitely.does.not.exist".to_string(),
            "example.com".to_string(),
        );

        let baseline_start = Instant::now();
        let baseline_result = Self::test_with_rcpt(
            conn,
            &invalid_target,
            mode,
            wrap,
            from_mail,
            timeout_secs,
            1,
        )
        .await;
        let baseline_duration = baseline_start.elapsed();
        let _ = baseline_result;

        // Test the actual user and compare timing
        // Do multiple timing measurements for increased accuracy
        let mut timing_results = Vec::with_capacity(3);
        let mut final_result = (UserStatus::Unknown, String::new(), String::new());

        for i in 0..3.min(retry_count) {
            if i > 0 {
                // Add a small delay between tests
                sleep(Duration::from_millis(200)).await;

                // Reset the connection
                let _ = conn.send_command("RSET", timeout_secs).await;
            }

            let real_test_start = Instant::now();
            let result =
                Self::test_with_rcpt(conn, target, mode, wrap, from_mail, timeout_secs, 1).await;
            let real_test_duration = real_test_start.elapsed();

            timing_results.push(real_test_duration);

            // If we get a definitive result, don't need to continue timing tests
            if result.0 == UserStatus::Valid || result.0 == UserStatus::Invalid {
                final_result = result;
                break;
            }

            // Save the last result
            final_result = result;
        }

        // Get median response time for more reliable measurement
        timing_results.sort_by_key(std::time::Duration::as_millis);
        let real_test_duration = if timing_results.is_empty() {
            Duration::from_millis(0)
        } else {
            timing_results[timing_results.len() / 2]
        };

        // If the server responds with the same error for all users
        // Check for significant timing difference that might indicate a valid user
        let baseline_ms = baseline_duration.as_millis();
        let test_ms = real_test_duration.as_millis();

        // More sophisticated timing analysis
        if (test_ms > baseline_ms * 2)
            || (test_ms > baseline_ms + 1000)
            || (baseline_ms < 100 && test_ms > 300)
        {
            return (
                UserStatus::Valid,
                format!("Timing difference detected: {test_ms}ms vs baseline {baseline_ms}ms"),
                final_result.2,
            );
        }

        // Otherwise, return the normal result
        final_result
    }

    // Combined test method using multiple techniques
    pub async fn test_combined(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        from_mail: &str,
        timeout_secs: u64,
        retry_count: u8,
        output_handler: &OutputHandler,
    ) -> (UserStatus, String, String) {
        // Try multiple methods and combine the results

        // Try VRFY first
        let vrfy_result =
            Self::test_with_vrfy(conn, target, mode, wrap, timeout_secs, 1, output_handler).await;
        if vrfy_result.0 == UserStatus::Valid {
            return vrfy_result;
        }

        // Then try EXPN
        let expn_result = Self::test_with_expn(conn, target, mode, wrap, timeout_secs, 1).await;
        if expn_result.0 == UserStatus::Valid {
            return expn_result;
        }

        // Finally try RCPT TO
        let rcpt_result = Self::test_with_rcpt(
            conn,
            target,
            mode,
            wrap,
            from_mail,
            timeout_secs,
            retry_count,
        )
        .await;

        // If any method returned valid, consider it valid
        if vrfy_result.0 == UserStatus::Valid
            || expn_result.0 == UserStatus::Valid
            || rcpt_result.0 == UserStatus::Valid
        {
            return (
                UserStatus::Valid,
                "Combined methods indicate valid user".to_string(),
                format!(
                    "VRFY: {}, EXPN: {}, RCPT: {}",
                    vrfy_result.2, expn_result.2, rcpt_result.2
                ),
            );
        }

        // If all methods returned invalid, consider it invalid
        if vrfy_result.0 == UserStatus::Invalid
            && expn_result.0 == UserStatus::Invalid
            && rcpt_result.0 == UserStatus::Invalid
        {
            return (
                UserStatus::Invalid,
                "Combined methods indicate invalid user".to_string(),
                format!(
                    "VRFY: {}, EXPN: {}, RCPT: {}",
                    vrfy_result.2, expn_result.2, rcpt_result.2
                ),
            );
        }

        // Otherwise, uncertain
        (
            UserStatus::Unknown,
            "Combined methods are inconclusive".to_string(),
            format!(
                "VRFY: {}, EXPN: {}, RCPT: {}",
                vrfy_result.2, expn_result.2, rcpt_result.2
            ),
        )
    }

    // Stealthy testing method
    pub async fn test_with_stealth(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        wrap: bool,
        from_mail: &str,
        timeout_secs: u64,
        retry_count: u8,
    ) -> (UserStatus, String, String) {
        // Stealth mode uses techniques designed to be less detectable

        // 1. Random delay between tests (1-1.5 seconds)
        let rand_delay = 1000
            + (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis()
                % 500) as u64;
        sleep(Duration::from_millis(rand_delay)).await;

        // 2. Use partial commands and RCPT TO with different client signatures
        let username_part = target.username.clone();
        let partial_cmd = format!("VRFY {username_part}");
        let partial_result = conn.send_command(&partial_cmd, timeout_secs).await;

        // Reset connection state
        let _ = conn.send_command("RSET", timeout_secs).await;

        // Add another delay to appear more like a human user
        sleep(Duration::from_millis(300)).await;

        // Use a different MAIL FROM to avoid pattern detection
        let alt_from = if from_mail.contains('@') {
            let parts: Vec<&str> = from_mail.split('@').collect();
            if parts.len() == 2 {
                // Add a random number to the username part
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                format!("{}{}@{}", parts[0], timestamp % 1000, parts[1])
            } else {
                from_mail.to_string()
            }
        } else {
            from_mail.to_string()
        };

        // Try the RCPT command with the altered FROM
        let rcpt_result = Self::test_with_rcpt(
            conn,
            target,
            mode,
            wrap,
            &alt_from,
            timeout_secs,
            retry_count / 2,
        )
        .await;

        // Analyze both results
        if let Ok(partial_response) = partial_result {
            if partial_response.contains("user") && partial_response.contains("exist") {
                // Likely an invalid user response
                return (
                    UserStatus::Invalid,
                    "Stealth check indicates invalid user".to_string(),
                    partial_response,
                );
            }
        } else { /* Ignore partial command errors */
        }

        // Add one more delay before returning
        sleep(Duration::from_millis(200)).await;

        // Default to the RCPT result
        rcpt_result
    }

    // Select the appropriate test method based on mode
    pub async fn test_user(
        conn: &mut SmtpConnection,
        target: &TestTarget,
        mode: &EnumMode,
        from_mail: &str,
        wrap: bool,
        timeout_secs: u64,
        retry_count: u8,
        output_handler: &OutputHandler,
    ) -> (UserStatus, String, String) {
        match mode {
            EnumMode::Auto => {
                // In Auto mode, we try different methods based on server capabilities
                if conn
                    .server_info
                    .capabilities
                    .iter()
                    .any(|c| c.contains("VRFY"))
                {
                    Self::test_with_vrfy(
                        conn,
                        target,
                        mode,
                        wrap,
                        timeout_secs,
                        retry_count,
                        output_handler,
                    )
                    .await
                } else if conn
                    .server_info
                    .capabilities
                    .iter()
                    .any(|c| c.contains("EXPN"))
                {
                    Self::test_with_expn(conn, target, mode, wrap, timeout_secs, retry_count).await
                } else {
                    Self::test_with_rcpt(
                        conn,
                        target,
                        mode,
                        wrap,
                        from_mail,
                        timeout_secs,
                        retry_count,
                    )
                    .await
                }
            }
            EnumMode::Vrfy => {
                Self::test_with_vrfy(
                    conn,
                    target,
                    mode,
                    wrap,
                    timeout_secs,
                    retry_count,
                    output_handler,
                )
                .await
            }
            EnumMode::Expn => {
                Self::test_with_expn(conn, target, mode, wrap, timeout_secs, retry_count).await
            }
            EnumMode::Rcpt => {
                Self::test_with_rcpt(
                    conn,
                    target,
                    mode,
                    wrap,
                    from_mail,
                    timeout_secs,
                    retry_count,
                )
                .await
            }
            EnumMode::Timing => {
                Self::test_with_timing(
                    conn,
                    target,
                    mode,
                    wrap,
                    from_mail,
                    timeout_secs,
                    retry_count,
                )
                .await
            }
            EnumMode::Combined => {
                Self::test_combined(
                    conn,
                    target,
                    mode,
                    wrap,
                    from_mail,
                    timeout_secs,
                    retry_count,
                    output_handler,
                )
                .await
            }
            EnumMode::Stealth => {
                Self::test_with_stealth(
                    conn,
                    target,
                    mode,
                    wrap,
                    from_mail,
                    timeout_secs,
                    retry_count,
                )
                .await
            }
        }
    }
}
