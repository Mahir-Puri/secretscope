//! SecretScope command line entry point.

mod config;
mod output;
mod run;

use clap::{Parser, Subcommand};
use run::{run, ScanArgs};

#[derive(Parser)]
#[command(
    name = "secretscope",
    about = "Find exposed credentials and analyze what they could reach",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a directory for credentials and analyze their blast radius.
    Scan(ScanArgs),
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Scan(args) => run(args),
    };
    std::process::exit(code);
}
