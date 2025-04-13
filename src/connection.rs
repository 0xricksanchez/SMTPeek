use colored::Colorize;
use std::io::{self, ErrorKind};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufStream};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::sync::OnceLock;
use tokio_rustls::TlsConnector;

// --- Global Crypto Provider Setup ---
// Install the desired provider based on features ONCE globally
static CRYPTO_PROVIDER_INSTALLATION: OnceLock<Result<(), rustls::Error>> = OnceLock::new();

fn install_crypto_provider(verbose: bool) -> Result<(), rustls::Error> {
    CRYPTO_PROVIDER_INSTALLATION
        .get_or_init(|| {
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            match provider.install_default() {
                Ok(()) => {
                    if verbose {
                        println!("Installed default rustls crypto provider (aws-lc-rs).");
                    }
                    Ok(())
                }
                Err(current_provider) => {
                    if verbose {
                        eprintln!(
                            "Default crypto provider already installed: {current_provider:?}. Using existing."
                        );
                    }
                    Ok(())
                }
            }
        })
        .clone()
}
// -----------------------------------

// Information about the SMTP server capabilities
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub capabilities: Vec<String>,
    pub supports_tls: bool,
    pub is_tls: bool,
    pub response_times: Vec<Duration>,
    pub banner: String,
    pub server_type: Option<String>,
}

// --- Enum to represent the stream type ---
enum StreamType {
    Plain(BufStream<TcpStream>),
    Tls(Box<BufStream<tokio_rustls::client::TlsStream<TcpStream>>>),
}

// Implement IO traits for the enum to simplify send_command/close
impl AsyncRead for StreamType {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamType {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
// --------------------------------------------

// A connection to an SMTP server
pub struct SmtpConnection {
    // Use the enum for the stream
    stream: StreamType,
    pub server_info: ServerInfo,
    pub last_activity: Instant,
    pub error_count: u8,
    pub max_errors: u8,
    #[allow(dead_code)]
    pub id: usize,
    #[allow(dead_code)]
    verbose: bool,
}

impl SmtpConnection {
    // Create a new connection with retry logic and TLS option
    pub async fn new(
        target: &str,
        port: u16,
        timeout_secs: u64,
        helo_domain: &str,
        fingerprint: bool,
        is_tls: bool,
        tls_enable_verify: bool,
        id: usize,
        verbose: bool,
    ) -> io::Result<Self> {
        if cfg!(debug_assertions) || verbose {
            eprintln!(
                "Creating SMTP connection #{id} to {target}:{port} (TLS requested: {is_tls})"
            );
        }

        // Create connection with exponential backoff on failure
        let max_attempts = 3;
        let mut last_error = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                // Exponential backoff: 1s, 2s, 4s...
                let backoff = Duration::from_secs(1 << attempt);
                tokio::time::sleep(backoff).await;
            }

            match Self::attempt_connection(
                target,
                port,
                timeout_secs,
                helo_domain,
                fingerprint,
                is_tls,
                tls_enable_verify,
                id,
                verbose,
            )
            .await
            {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_error = Some(e);
                    // Continue to next attempt
                }
            }
        }

        // All attempts failed
        Err(last_error.unwrap_or_else(|| io::Error::other("Failed to establish SMTP connection")))
    }

    // --- Helper to Build TLS Config ---
    fn build_tls_config(
        danger_skip_verify: bool,
        id: usize,
        verbose: bool,
    ) -> io::Result<ClientConfig> {
        install_crypto_provider(cfg!(debug_assertions) || verbose)
            .map_err(|e| io::Error::other(format!("Crypto provider error: {e}")))?;

        let builder = ClientConfig::builder();

        let config = if danger_skip_verify {
            if verbose {
                println!(
                    "{} Skipping TLS certificate verification for Conn #{}",
                    "[!]".red().bold(),
                    id
                );
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
                .with_no_client_auth()
        } else {
            if verbose {
                println!(
                    "{} Using platform certificate verifier for Conn #{}",
                    "[D]".dimmed(),
                    id
                );
            }
            let platform_verifier = rustls_platform_verifier::Verifier::new();
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(platform_verifier))
                .with_no_client_auth()
        };
        Ok(config)
    }

    async fn try_starttls_upgrade(
        // Takes ownership of the plain stream
        mut buffered_plain: BufStream<TcpStream>,
        helo_domain: &str,
        timeout_duration: Duration,
        target: &str,
        tls_enable_verify: bool,
        id: usize,
        verbose: bool,
    ) -> io::Result<(StreamType, Vec<String>)> {
        if verbose {
            println!(
                "{} Attempting STARTTLS upgrade for Conn #{id}...",
                "[>]".yellow().bold()
            );
        }

        // Send STARTTLS command using the owned plain stream
        buffered_plain.write_all(b"STARTTLS\r\n").await?;
        buffered_plain.flush().await?;

        // Read STARTTLS response (should be single line 220)
        let mut starttls_response = String::new();
        // Use BufReader temporarily just for this read_line on the plain stream
        // Need to ensure BufReader doesn't interfere with ownership if read fails partially
        // Reading directly might be simpler here if BufReader complicates ownership management
        match timeout(
            timeout_duration,
            buffered_plain.read_line(&mut starttls_response),
        )
        .await
        {
            Ok(Ok(0)) => Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "Connection closed after STARTTLS command",
            )),
            Ok(Ok(_)) if starttls_response.starts_with("220") => {
                // --- Configure TLS ---
                let danger_skip_verify = !tls_enable_verify;
                let tls_config = Self::build_tls_config(danger_skip_verify, id, verbose)?;
                let connector = TlsConnector::from(Arc::new(tls_config));
                let server_name = ServerName::try_from(target.to_string()).map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid DNS name '{target}': {e}"),
                    )
                })?;
                let plain_tcp_stream = buffered_plain.into_inner();

                // Perform TLS handshake
                let tls_stream_future = connector.connect(server_name, plain_tcp_stream);

                match timeout(timeout_duration, tls_stream_future).await {
                    Ok(Ok(tls_stream)) => {
                        if verbose {
                            println!(
                                "{} STARTTLS handshake successful for Conn #{}.",
                                "[+]".green().bold(),
                                id
                            );
                        }
                        let mut buffered_tls = BufStream::new(tls_stream);
                        if verbose {
                            println!(
                                "{} Sending EHLO again over TLS for Conn #{}...",
                                "[D]".dimmed(),
                                id
                            );
                        }

                        // Call helper directly, no need for Self::
                        let tls_capabilities =
                            Self::send_ehlo(&mut buffered_tls, helo_domain, timeout_duration)
                                .await?;
                        if tls_capabilities.is_empty() || !tls_capabilities[0].starts_with("250") {
                            eprintln!(
                                "{} EHLO over TLS failed after STARTTLS for Conn #{}.",
                                "[-]".red().bold(),
                                id
                            );
                            return Err(io::Error::other(
                                "EHLO command failed after successful TLS handshake",
                            ));
                        }
                        if verbose {
                            println!(
                                "{} Received new capabilities over TLS for Conn #{}.",
                                "[D]".dimmed(),
                                id
                            );
                        }
                        // Return the successful TLS stream state and new capabilities
                        Ok((StreamType::Tls(Box::new(buffered_tls)), tls_capabilities))
                    }
                    Ok(Err(e)) => {
                        eprintln!("[Conn #{id}] TLS handshake failed: {e}");
                        Err(io::Error::new(
                            ErrorKind::ConnectionAborted,
                            format!("TLS handshake error: {e}"),
                        ))
                    }
                    Err(_) => {
                        eprintln!("[Conn #{id}] TLS handshake timed out.");
                        Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "TLS handshake timed out",
                        ))
                    }
                }
            }

            Ok(Ok(_)) => {
                eprintln!(
                    "{} Unexpected response to STARTTLS for Conn #{}: {}",
                    "[-]".red().bold(),
                    id,
                    starttls_response.trim()
                );
                Err(io::Error::other(format!(
                    "Unexpected STARTTLS response: {}",
                    starttls_response.trim()
                )))
            }
            Ok(Err(e)) => {
                eprintln!(
                    "{} Error reading STARTTLS response for Conn #{}: {}",
                    "[-]".red().bold(),
                    id,
                    e
                );
                Err(e)
            }
            Err(_) => {
                eprintln!(
                    "{} Timed out waiting for STARTTLS response for Conn #{}.",
                    "[-]".red().bold(),
                    id
                );
                Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Timeout reading STARTTLS response",
                ))
            }
        }
    }

    // Attempt to establish a connection, potentially upgrading to TLS
    async fn attempt_connection(
        target: &str,
        port: u16,
        timeout_secs: u64,
        helo_domain: &str,
        fingerprint: bool,
        is_tls: bool,
        tls_enable_verify: bool,
        id: usize,
        verbose: bool,
    ) -> io::Result<Self> {
        let timeout_duration = Duration::from_secs(timeout_secs);

        // --- Establish Base TCP Connection ---
        let addrs = format!("{target}:{port}")
            .to_socket_addrs()?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(io::Error::new(ErrorKind::NotFound, "Could not resolve"));
        }
        let conn_future = TcpStream::connect(addrs[0]);
        let tcp_stream = match timeout(timeout_duration, conn_future).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "TCP Connection timed out",
                ));
            }
        };
        tcp_stream.set_nodelay(true)?;

        // --- Variables for final state ---
        let final_stream: StreamType;
        let mut server_info: ServerInfo; // Will be initialized differently based on path
        let mut final_capabilities: Vec<String>;

        #[allow(unused_assignments)]
        let mut connection_is_tls = false;

        // --- Determine Connection Path ---
        let is_implicit_tls_port = port == 465; // Standard implicit TLS port

        if is_tls && is_implicit_tls_port {
            // --- IMPLICIT TLS Path ---
            if verbose {
                println!(
                    "{} Attempting Implicit TLS handshake on port {port} for Conn #{id}...",
                    "[>]".yellow().bold()
                );
            }
            let danger_skip_verify = !tls_enable_verify; // NOTE: False == skip verification
            let tls_config = Self::build_tls_config(danger_skip_verify, id, verbose)?;
            let connector = TlsConnector::from(Arc::new(tls_config));
            let server_name = ServerName::try_from(target.to_string()).map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid DNS name '{target}': {e}"),
                )
            })?;

            let tls_stream_future = connector.connect(server_name, tcp_stream); // Consumes tcp_stream

            let tls_stream = match timeout(timeout_duration, tls_stream_future).await {
                Ok(Ok(s)) => {
                    if verbose {
                        println!(
                            "{} Implicit TLS handshake successful for Conn #{id}.",
                            "[+]".green().bold()
                        );
                    }
                    s
                }
                Ok(Err(e)) => {
                    eprintln!(
                        "{} Implicit TLS handshake failed for Conn #{id}: {e}",
                        "[-]".red().bold()
                    );
                    return Err(io::Error::new(
                        ErrorKind::ConnectionRefused,
                        format!("Implicit TLS handshake failed: {e}"),
                    ));
                }
                Err(_) => {
                    eprintln!(
                        "{} Implicit TLS handshake timed out for Conn #{id}.",
                        "[-]".red().bold()
                    );
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "Implicit TLS handshake timed out",
                    ));
                }
            };

            let mut buffered_tls = BufStream::new(tls_stream);
            connection_is_tls = true;

            // Read banner OVER TLS now
            let mut banner = String::new();
            match timeout(timeout_duration, buffered_tls.read_line(&mut banner)).await {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        ErrorKind::ConnectionAborted,
                        "Closed after TLS before banner",
                    ));
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(io::Error::other(format!(
                        "Error reading banner over TLS: {e}"
                    )));
                }
                Err(_) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "Timeout reading banner over TLS",
                    ));
                }
            }
            // Initialize server_info AFTER successful TLS connection and banner read
            server_info = ServerInfo {
                banner: banner.trim().to_string(),
                capabilities: Vec::new(),
                supports_tls: true,
                is_tls: connection_is_tls,
                response_times: Vec::new(),
                server_type: None,
            };

            // Send EHLO/HELO OVER TLS
            final_capabilities =
                Self::send_ehlo(&mut buffered_tls, helo_domain, timeout_duration).await?;
            if final_capabilities.is_empty() || !final_capabilities[0].starts_with("250") {
                final_capabilities =
                    Self::send_helo(&mut buffered_tls, helo_domain, timeout_duration).await?;
            }
            final_stream = StreamType::Tls(Box::new(buffered_tls));
        } else {
            // --- STANDARD / STARTTLS Path ---
            let mut buffered_plain = BufStream::new(tcp_stream); // Use the tcp_stream here

            // Read Plaintext Banner first
            let mut banner = String::new();
            match timeout(timeout_duration, buffered_plain.read_line(&mut banner)).await {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        ErrorKind::ConnectionAborted,
                        "Closed before banner",
                    ));
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "Timeout reading banner",
                    ));
                }
            }
            // Initialize server_info based on plaintext banner read
            server_info = ServerInfo {
                banner: banner.trim().to_string(),
                capabilities: Vec::new(),
                supports_tls: false,
                is_tls: false, // Initially not TLS
                response_times: Vec::new(),
                server_type: None,
            };

            // Initial EHLO/HELO (Plaintext)
            let mut initial_capabilities =
                Self::send_ehlo(&mut buffered_plain, helo_domain, timeout_duration).await?;
            if initial_capabilities.is_empty() || !initial_capabilities[0].starts_with("250") {
                initial_capabilities =
                    Self::send_helo(&mut buffered_plain, helo_domain, timeout_duration).await?;
            }
            server_info.capabilities.clone_from(&initial_capabilities);
            server_info.supports_tls = initial_capabilities
                .iter()
                .any(|c| c.to_uppercase().contains("STARTTLS"));

            // Attempt STARTTLS if requested and supported
            if is_tls && server_info.supports_tls {
                // Call helper which consumes buffered_plain
                match Self::try_starttls_upgrade(
                    buffered_plain,
                    helo_domain,
                    timeout_duration,
                    target,
                    tls_enable_verify,
                    id,
                    verbose,
                )
                .await
                {
                    Ok((tls_stream_type, tls_caps)) => {
                        final_stream = tls_stream_type;
                        final_capabilities = tls_caps;
                        connection_is_tls = true; // Mark as using TLS now
                    }
                    Err(e) => {
                        // TLS upgrade failed
                        eprintln!(
                            "[Conn #{id}] STARTTLS upgrade failed: {e}. Aborting connection."
                        );
                        return Err(e); // Return error, don't try to continue plaintext
                    }
                }
            } else {
                // No STARTTLS needed/possible
                final_stream = StreamType::Plain(buffered_plain);
                final_capabilities = initial_capabilities;
                connection_is_tls = false;
            }
        }

        // --- Final Steps ---
        server_info.capabilities.clone_from(&final_capabilities);
        server_info.is_tls = connection_is_tls;

        if fingerprint {
            server_info.server_type =
                Self::fingerprint_server(&final_capabilities, &server_info.banner);
            if let Some(ref server_type) = server_info.server_type {
                println!(
                    "{} Identified server type: {server_type} for Conn #{id} via fingerprinting",
                    "[+]".green().bold()
                );
            } else {
                println!(
                    "{} Could not identify server type for Conn #{id} via fingerprinting",
                    "[!]".red().bold()
                );
            }
        }

        Ok(Self {
            stream: final_stream,
            server_info,
            last_activity: Instant::now(),
            error_count: 0,
            max_errors: 5,
            id,
            verbose,
        })
    }

    // Helper function to send EHLO and read response
    async fn send_ehlo<S>(
        stream: &mut S,
        helo_domain: &str,
        timeout_duration: Duration,
    ) -> io::Result<Vec<String>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if cfg!(debug_assertions) {
            eprintln!("Sending: EHLO {helo_domain}");
        }
        let ehlo_cmd = format!("EHLO {helo_domain}\r\n");
        stream.write_all(ehlo_cmd.as_bytes()).await?;
        stream.flush().await?;
        Self::read_multiline_response(stream, timeout_duration).await
    }

    // Helper function to send HELO and read response
    async fn send_helo<S>(
        stream: &mut S,
        helo_domain: &str,
        timeout_duration: Duration,
    ) -> io::Result<Vec<String>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if cfg!(debug_assertions) {
            eprintln!("Sending: HELO {helo_domain}");
        }
        let helo_cmd = format!("HELO {helo_domain}\r\n");
        stream.write_all(helo_cmd.as_bytes()).await?;
        stream.flush().await?;
        let mut response = String::new();
        // Use BufReader for read_line on the underlying stream
        let mut reader = BufReader::new(stream);
        let read_future = reader.read_line(&mut response); // HELO is typically single line
        match timeout(timeout_duration, read_future).await {
            Ok(Ok(0)) => Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "Connection closed during HELO response",
            )),
            Ok(Ok(_)) => {
                if cfg!(debug_assertions) {
                    eprintln!("Received: {}", response.trim());
                }
                Ok(vec![response.trim().to_string()])
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                ErrorKind::TimedOut,
                "Timed out waiting for HELO response",
            )),
        }
    }

    // Helper to read potentially multiline SMTP responses using BufReader for efficiency
    async fn read_multiline_response<S>(
        stream: &mut S,
        timeout_duration: Duration,
    ) -> io::Result<Vec<String>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut lines = Vec::new();
        // Wrap the stream reference in BufReader for efficient line reading
        let mut reader = BufReader::new(stream);
        let mut line_buffer = String::new();

        loop {
            line_buffer.clear();
            let read_future = reader.read_line(&mut line_buffer);
            match timeout(timeout_duration, read_future).await {
                Ok(Ok(0)) => {
                    // Connection closed
                    if lines.is_empty() {
                        return Err(io::Error::new(
                            ErrorKind::ConnectionAborted,
                            "Connection closed before response",
                        ));
                    }
                    break; // Treat as end of response if we got something
                }
                Ok(Ok(_bytes_read)) => {
                    let trimmed_line = line_buffer.trim();
                    if cfg!(debug_assertions) {
                        eprintln!("Received Line: {trimmed_line}");
                    }
                    if trimmed_line.is_empty() {
                        // Ignore empty lines potentially sent by some servers
                        continue;
                    }
                    lines.push(trimmed_line.to_string());
                    // Check for standard SMTP multiline end condition (3-digit code followed by SPACE)
                    if trimmed_line.len() >= 4
                        && trimmed_line.chars().take(3).all(|c| c.is_ascii_digit())
                        && trimmed_line.chars().nth(3) == Some(' ')
                    {
                        break; // Last line received
                    }
                }
                Ok(Err(e)) => {
                    // Read error
                    eprintln!("Error reading response line: {e}");
                    return Err(e);
                }
                Err(_) => {
                    // Timeout
                    eprintln!("Timed out reading response line.");
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "Timed out reading response",
                    ));
                }
            }
        }
        if cfg!(debug_assertions) {
            eprintln!("Full Response Lines: {lines:?}");
        }
        Ok(lines)
    }

    // Attempt to identify the server type from banner and capabilities
    fn fingerprint_server(capabilities: &[String], banner: &str) -> Option<String> {
        let banner_lower = banner.to_lowercase();

        // Prioritize banner checks
        if banner_lower.contains("postfix") {
            return Some("Postfix".to_string());
        }
        if banner_lower.contains("exim") {
            return Some("Exim".to_string());
        }
        if banner_lower.contains("microsoft") || banner_lower.contains("exchange") {
            return Some("Microsoft Exchange".to_string());
        }
        if banner_lower.contains("sendmail") {
            return Some("Sendmail".to_string());
        }
        if banner_lower.contains("google") {
            return Some("Google GFE/Gmail".to_string());
        } // Example addition
        if banner_lower.contains("outlook.com") {
            return Some("Microsoft Outlook.com".to_string());
        } // Example addition
        if banner_lower.contains("zimbra") {
            return Some("Zimbra".to_string());
        }
        if banner_lower.contains("courier") {
            return Some("Courier".to_string());
        }
        if banner_lower.contains("qmail") {
            return Some("qmail".to_string());
        }

        // Fallback to capability checks
        for cap in capabilities {
            let cap_lower = cap.to_lowercase();
            // Avoid redundant checks if already found in banner
            if cap_lower.contains("postfix") {
                return Some("Postfix".to_string());
            }
            if cap_lower.contains("exim") {
                return Some("Exim".to_string());
            }
            if cap_lower.contains("microsoft") || cap_lower.contains("exchange") {
                return Some("Microsoft Exchange".to_string());
            }
            // TODO:Add other capability-based fingerprints if known
        }

        None // Could not identify
    }

    // Send a command to the server and get the response
    pub async fn send_command(&mut self, command: &str, timeout_secs: u64) -> io::Result<String> {
        let now = Instant::now();
        // Check if connection is stale (e.g., inactive for more than 2 minutes)
        if now.duration_since(self.last_activity) > Duration::from_secs(120) {
            // Optionally try to send a NOOP first to revive? Or just error out.
            return Err(io::Error::new(ErrorKind::TimedOut, "Connection is stale"));
        }
        // Update activity time immediately before starting the operation
        self.last_activity = now;

        // Check if we've exceeded the error threshold
        if self.error_count >= self.max_errors {
            return Err(io::Error::other("Too many errors on this connection"));
        }

        let timeout_duration = Duration::from_secs(timeout_secs);

        // Format command with CRLF if needed
        let cmd_with_crlf = if command.ends_with("\r\n") {
            command.to_string()
        } else {
            format!("{command}\r\n")
        };

        // Debug print if enabled
        if cfg!(debug_assertions) {
            // Avoid printing sensitive commands if necessary in the future
            eprintln!(
                "[Conn #{}] Sending Command: {}",
                self.id,
                command.trim_end()
            );
        }

        // --- Send command with timeout ---
        match timeout(
            timeout_duration,
            self.stream.write_all(cmd_with_crlf.as_bytes()),
        )
        .await
        {
            Ok(Ok(())) => {} // Inner write succeeded
            Ok(Err(io_err)) => {
                // Inner write failed with IO error
                eprintln!(
                    "[Conn #{}] IO Error writing command '{}': {}",
                    self.id,
                    command.trim_end(),
                    io_err
                );
                self.error_count += 1;
                return Err(io_err);
            }
            Err(_elapsed) => {
                // Outer timeout error (Elapsed)
                eprintln!(
                    "[Conn #{}] Timeout writing command '{}'",
                    self.id,
                    command.trim_end()
                );
                self.error_count += 1;
                // Convert Elapsed to TimedOut IO error
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Timeout writing command",
                ));
            }
        }

        // --- Flush stream with timeout ---
        match timeout(timeout_duration, self.stream.flush()).await {
            Ok(Ok(())) => {} // Inner flush succeeded
            Ok(Err(io_err)) => {
                // Inner flush failed
                eprintln!(
                    "[Conn #{}] IO Error flushing command '{}': {}",
                    self.id,
                    command.trim_end(),
                    io_err
                );
                self.error_count += 1;
                return Err(io_err);
            }
            Err(_elapsed) => {
                // Outer timeout error (Elapsed)
                eprintln!(
                    "[Conn #{}] Timeout flushing command '{}'",
                    self.id,
                    command.trim_end()
                );
                self.error_count += 1;
                // Convert Elapsed to TimedOut IO error
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Timeout flushing command",
                ));
            }
        }

        // --- Read response ---
        match Self::read_multiline_response(&mut self.stream, timeout_duration).await {
            Ok(lines) => {
                // Store the response time based on when command was initiated
                let response_time = now.elapsed();
                self.server_info.response_times.push(response_time);

                // Debug print if enabled
                if cfg!(debug_assertions) {
                    eprintln!(
                        "[Conn #{}] Received Response ({}ms): {:?}",
                        self.id,
                        response_time.as_millis(),
                        lines.first().map_or("<empty>", |l| l.trim()) // Log first line compactly
                    );
                }
                // Return the full response joined by newlines
                Ok(lines.join("\n"))
            }
            Err(e) => {
                eprintln!(
                    "[Conn #{}] Error receiving response for '{}': {}",
                    self.id,
                    command.trim_end(),
                    e
                );
                self.error_count += 1; // Increment error count on read failure too
                Err(e)
            }
        }
    }

    // Gracefully close the connection
    pub async fn close(&mut self) -> io::Result<()> {
        if cfg!(debug_assertions) {
            eprintln!("[Conn #{}] Closing connection.", self.id);
        }
        // Send QUIT using the stream wrapper, ignore errors often
        let quit_future = async {
            self.stream.write_all(b"QUIT\r\n").await?;
            self.stream.flush().await
        };
        // Short timeout for QUIT
        match timeout(Duration::from_secs(5), quit_future).await {
            Ok(Ok(())) => {} // Quit sent okay
            Ok(Err(e)) => {
                if cfg!(debug_assertions) {
                    eprintln!("[Conn #{}] Error sending QUIT: {}", self.id, e);
                }
            }
            Err(_) => {
                if cfg!(debug_assertions) {
                    eprintln!("[Conn #{}] Timeout sending QUIT.", self.id);
                }
            }
        }

        // Shutdown the stream gracefully (important for TLS)
        let shutdown_future = self.stream.shutdown();
        match timeout(Duration::from_secs(5), shutdown_future).await {
            Ok(Ok(())) => {} // Shutdown okay
            Ok(Err(e)) => {
                if cfg!(debug_assertions) {
                    eprintln!("[Conn #{}] Error shutting down stream: {}", self.id, e);
                }
            }
            Err(_) => {
                if cfg!(debug_assertions) {
                    eprintln!("[Conn #{}] Timeout shutting down stream.", self.id);
                }
            }
        }
        Ok(())
    }
}

// --- Module for Dangerous TLS Config (Use with extreme caution) ---
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::verify_tls12_signature;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        // Dangerously verify any certificate
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        // Use default verification logic for signatures (important!)
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                // Use the default provider's algorithms
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        // Use default verification logic for signatures (important!)
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                // Use the default provider's algorithms
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        // Provide supported schemes from the default provider
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
// ---------------------------------------------------------------------

// Connection pool with management and TLS awareness
pub struct ConnectionPool {
    connections: Vec<SmtpConnection>,
    host: String,
    port: u16,
    helo: String,
    timeout: u64,
    fingerprint: bool,
    max_size: usize,
    next_id: usize,
    semaphore: Arc<Semaphore>,
    is_tls: bool,
    tls_verify: bool,
    verbose: bool,
}

impl ConnectionPool {
    pub fn new(
        host: String,
        port: u16,
        helo: String,
        timeout: u64,
        fingerprint: bool,
        is_tls: bool,
        tls_verify: bool,
        max_size: usize,
        verbose: bool,
    ) -> Self {
        Self {
            connections: Vec::with_capacity(max_size),
            host,
            port,
            helo,
            timeout,
            fingerprint,
            is_tls,
            tls_verify,
            max_size,
            next_id: 1,
            semaphore: Arc::new(Semaphore::new(max_size)),
            verbose,
        }
    }

    // Get a connection from the pool or create a new one
    pub async fn get_connection(&mut self) -> io::Result<SmtpConnection> {
        // Acquire permit first, potentially waiting
        let permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| io::Error::other("Semaphore closed"))?;

        // Try to reuse an existing connection from the pool
        while let Some(mut conn) = self.connections.pop() {
            // Check errors/staleness AND send NOOP to verify liveness
            let noop_check_future = conn.send_command("NOOP", 5); // Use short timeout for NOOP
            match timeout(Duration::from_secs(5), noop_check_future).await {
                Ok(Ok(ref response)) if response.starts_with("250") => {
                    // NOOP ok and basic checks passed
                    if conn.error_count < conn.max_errors
                        && conn.last_activity.elapsed() < Duration::from_secs(60)
                    {
                        if cfg!(debug_assertions) || self.verbose {
                            eprintln!("[Pool] Reusing connection #{}", conn.id);
                        }
                        conn.last_activity = Instant::now();
                        std::mem::forget(permit);
                        return Ok(conn);
                    }
                    // NOOP ok, but stale or too many errors reported previously
                    if cfg!(debug_assertions) || self.verbose {
                        eprintln!(
                            "[Pool] Dropping connection #{} (stale/errors) despite NOOP success.",
                            conn.id
                        );
                    }
                }
                _ => {
                    // NOOP failed or timed out
                    if cfg!(debug_assertions) || self.verbose {
                        eprintln!(
                            "[Pool] Dropping bad connection #{} after NOOP check failed/timeout.",
                            conn.id
                        );
                    }
                }
            }
            // If we reach here, the connection was bad
            let _ = conn.close().await; // Attempt close
            // Permit is still held, loop to try next connection
        }

        // No reusable connection found, create a new one
        if cfg!(debug_assertions) || self.verbose {
            eprintln!("[Pool] Creating new connection.");
        }
        let conn_id = self.next_id;
        self.next_id += 1;

        // Create the new connection, passing the stored `is_tls` flag
        match SmtpConnection::new(
            &self.host,
            self.port,
            self.timeout,
            &self.helo,
            self.fingerprint,
            self.is_tls,
            self.tls_verify,
            conn_id,
            self.verbose,
        )
        .await
        {
            Ok(conn) => {
                // Don't drop the permit, associate it with the new connection
                std::mem::forget(permit);
                Ok(conn)
            }
            Err(e) => {
                // Connection failed, permit *is* dropped automatically here by RAII
                Err(e)
            }
        }
    }

    // Return a connection to the pool for reuse
    pub fn return_connection(&mut self, conn: SmtpConnection) {
        let should_return = conn.error_count < conn.max_errors
            && conn.last_activity.elapsed() < Duration::from_secs(60)
            && self.connections.len() < self.max_size;

        if should_return {
            if cfg!(debug_assertions) || self.verbose {
                eprintln!("[Pool] Returning connection #{} to pool.", conn.id);
            }
            self.connections.push(conn);
            // Connection returned successfully, release its permit back to semaphore
            self.semaphore.add_permits(1);
        } else {
            // Connection is bad or pool full, let it drop.
            // Since we used mem::forget in get_connection, the permit associated
            // with this connection instance is NOT automatically returned when `conn`
            // is dropped here. This effectively reduces the available permits,
            // reflecting that the connection slot is now unusable until a new
            // connection succeeds. This logic seems correct IF mem::forget is used.
            // *Alternative*: Don't use mem::forget, let permit drop here, and only call
            // add_permits above. Choose one consistent approach. Let's stick with mem::forget for now.
            if cfg!(debug_assertions) || self.verbose {
                eprintln!(
                    "[Pool] Not returning connection #{} (Errors: {}, Elapsed: {:?}, Pool size: {}). Permit effectively consumed.",
                    conn.id,
                    conn.error_count,
                    conn.last_activity.elapsed(),
                    self.connections.len()
                );
            }
        }
    }

    // Get the number of active connections (conceptually acquired permits)
    #[allow(dead_code)]
    pub fn active_connections(&self) -> usize {
        self.max_size - self.semaphore.available_permits()
    }

    // Get the maximum connections allowed
    #[allow(dead_code)]
    pub fn max_connections(&self) -> usize {
        self.max_size
    }
}

// Utility functions for analyzing SMTP responses
pub mod response_analysis {
    // Check if a response indicates a permanent error (5xx)
    pub fn is_permanent_error(response: &str) -> bool {
        response.starts_with('5')
            && response.len() >= 3
            && response.chars().take(3).all(|c| c.is_ascii_digit())
    }

    // Check if a response indicates a temporary error (4xx)
    pub fn is_temporary_error(response: &str) -> bool {
        response.starts_with('4')
            && response.len() >= 3
            && response.chars().take(3).all(|c| c.is_ascii_digit())
    }

    // Check if a response indicates success (2xx)
    pub fn is_success(response: &str) -> bool {
        response.starts_with('2')
            && response.len() >= 3
            && response.chars().take(3).all(|c| c.is_ascii_digit())
    }

    // Check if a response likely indicates an invalid user
    pub fn is_invalid_user(response: &str) -> bool {
        let lower = response.to_lowercase();
        response.starts_with("550")
            || response.starts_with("551") // User not local; please try <forward-path>
            || response.starts_with("553") // Requested action not taken: mailbox name not allowed
            || lower.contains("user unknown")
            || lower.contains("recipient rejected")
            || lower.contains("recipient address rejected")
            || lower.contains("no such user")
            || lower.contains("invalid mailbox")
            || lower.contains("mailbox unavailable")
            || lower.contains("does not exist")
            || lower.contains("address invalid")
    }

    // Check if a response likely indicates a valid user (usually 250/251 for RCPT TO)
    pub fn is_valid_user(response: &str) -> bool {
        response.starts_with("250") || response.starts_with("251") // 251 User not local; will forward
    }

    // Check if a response indicates ambiguous status (e.g., 252 cannot VRFY user)
    pub fn is_ambiguous(response: &str) -> bool {
        response.starts_with("252")
    }
}
