use rust_mcp_remote::logging::log;
use rust_mcp_remote::utils::{early_exit_output, parse_command_line_args_to};

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(output) = early_exit_output(&args, USAGE) {
        print!("{output}");
        std::process::exit(0);
    }
    match parse_command_line_args_to(&mut std::io::stderr(), args, USAGE) {
        Ok(Some(_)) => {}
        Ok(None) => std::process::exit(1),
        Err(error) => {
            log(&format!("Fatal error: {error}"), &[]);
            std::process::exit(1);
        }
    }
}
