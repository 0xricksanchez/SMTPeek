mod app;
mod cli;
mod connection;
mod input;
mod output;
mod target;
mod test_methods;

use std::process::ExitCode;

use app::App;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let app = App::new(cli);
    // Execute app.run() and handle the result explicitly
    match app.run().await {
        Ok(()) => {
            // Operation completed without returning an IO error
            ExitCode::SUCCESS
        }
        Err(_e) => {
            // An error occurred and was propagated up.
            // It was likely already printed in a user-friendly way
            // by the OutputHandler or within App methods.
            // Avoiding to print the raw Debug format again here.
            // eprintln!("\nApplication exited due to an error: {}", e);
            ExitCode::FAILURE
        }
    }
}
