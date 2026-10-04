#![forbid(unsafe_code)]

use dns_proxy::config::Config;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

const USAGE: &str = "usage: dns-proxy [--config <path>] [--check]

  --config <path>  configuration file (default /etc/dns-proxy/config.toml)
  --check          validate configuration and certificates, then exit
  --version        print version";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let mut config = PathBuf::from("/etc/dns-proxy/config.toml");
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => config = p.into(),
                None => return usage(),
            },
            "--check" => check = true,
            "--version" | "-V" => {
                println!("dns-proxy {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => return usage(),
        }
    }

    let cfg = match Config::load(&config) {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if check {
        return match dns_proxy::check(&cfg) {
            Ok(()) => {
                println!("configuration OK");
                ExitCode::SUCCESS
            }
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        };
    }

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

async fn run(cfg: Config) -> Result<(), String> {
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let proxy = dns_proxy::start(cfg).await?;
    tokio::select! {
        _ = term.recv() => info!("SIGTERM, shutting down"),
        _ = int.recv() => info!("SIGINT, shutting down"),
        _ = proxy.join() => return Err("listener task ended unexpectedly".into()),
    }
    Ok(())
}
