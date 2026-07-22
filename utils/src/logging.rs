use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Initialize the logging system based on the provided log level.
///
/// Supports two formats:
/// - "text": human-readable (default)
/// - "json": structured JSON output
pub fn init_logging(level: &str, format: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            let subscriber = fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(true)
                .with_line_number(true);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(subscriber)
                .init();
        }
        _ => {
            let subscriber = fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(true)
                .with_line_number(true);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(subscriber)
                .init();
        }
    }
}
