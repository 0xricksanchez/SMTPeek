use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(
    about = "Modern SMTP user enumeration tool with advanced features",
    long_about = "A state-of-the-art SMTP user enumeration tool that efficiently tests for valid email accounts on SMTP servers while evading detection mechanisms."
)]
pub struct Cli {
    // Required Connection Parameters
    /// Target host (IP address or hostname)
    #[arg(help = "Target SMTP server hostname or IP address")]
    pub host: String,

    /// Target port
    #[arg(help = "Target SMTP server port", default_value = "25")]
    pub port: u16,

    // Authentication and Identity Parameters
    /// HELO/EHLO domain
    #[arg(short = 'l', long)]
    pub helo: Option<String>,

    /// Sender email address for MAIL FROM
    #[arg(short = 'f', long, default_value = "friendly-scanner@example.com")]
    pub from_mail: String,

    // Enumeration Parameters
    /// Username or path to username wordlist
    #[arg(short, long, help = "Single username or path to username wordlist")]
    pub user: String,

    /// Domain to append to usernames (or path to domain wordlist for multiple domains)
    #[arg(
        short,
        long,
        help = "Domain to append to usernames (e.g., example.com) or path to domain wordlist"
    )]
    pub domain: Option<String>,

    /// Enumeration mode
    #[arg(short, long, value_enum, default_value = "auto")]
    pub mode: EnumMode,

    /// Wrap email addresses in angle brackets
    #[arg(short, long)]
    pub wrap: bool,

    // Connection and Network Settings
    /// Enable TLS if supported
    #[arg(short = 's', long)]
    pub tls: bool,

    // Enables TLS certificate verification
    #[arg(long = "tls-verify", default_value = "false", action=clap::ArgAction::SetTrue)]
    pub tls_verify: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Retry attempts per command
    #[arg(long, default_value = "3")]
    pub retry: u8,

    /// Connection pool size (for reusing connections)
    #[arg(long, default_value = "5")]
    pub pool_size: usize,

    #[arg(long)]
    pub skip_pool_check: bool,

    // Performance and Timing Options
    /// Number of concurrent connections to use. Only relevant for large wordlists. May hang if set
    /// too high. Only use if you know what you're doing.
    #[arg(short = 'c', long, default_value = "3")]
    pub concurrency: usize,

    /// Time delay between requests in milliseconds
    #[arg(long, default_value = "100")]
    pub delay: u64,

    /// Use adaptive delays based on server response times
    #[arg(long)]
    pub adaptive_delay: bool,

    /// Randomize testing order
    #[arg(short = 'r', long)]
    pub randomize: bool,

    // Output and Display Options
    /// Output format
    #[arg(short = 'o', long, value_enum, default_value = "standard")]
    pub output: OutputFormat,

    /// Verbose output mode
    #[arg(short, long)]
    pub verbose: bool,

    /// Live mode showing real-time test results
    #[arg(short = 'L', long)]
    pub live: bool,

    /// Colorful output (disable for logging to files)
    #[arg(short = 'C', long="no-color", default_value = "true", action=clap::ArgAction::SetFalse)]
    pub is_color: bool,

    /// Output file for results
    #[arg(long)]
    pub output_file: Option<PathBuf>,

    // Advanced Features
    /// Enable passive fingerprinting of SMTP server
    #[arg(long)]
    pub fingerprint: bool,
    // TODO: Detect and evade anti-enumeration mechanisms
    //#[arg(long)]
    //pub evasion: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum EnumMode {
    /// Automatically select the best method based on server responses
    Auto,
    /// VRFY command (verify user)
    Vrfy,
    /// EXPN command (expand mailing list)
    Expn,
    /// RCPT TO command (recipient)
    Rcpt,
    /// Use timing differences in responses
    Timing,
    /// Try multiple methods and combine results
    Combined,
    /// Use more stealthy techniques that may evade detection
    Stealth,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Standard colored output
    Standard,
    /// JSON format
    Json,
    /// CSV format
    Csv,
    /// Machine-readable format
    Machine,
}
