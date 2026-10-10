use rust_mcp_remote::utils::select_callback_port_to;

fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

#[test]
fn uses_the_specified_port_and_logs_it() {
    let mut console = Vec::new();

    let port = select_callback_port_to(&mut console, Some(8080), 3335);

    assert_eq!(port, 8080);
    let pid = std::process::id();
    assert_eq!(
        console_text(console),
        format!("[{pid}] Using specified callback port: 8080\n")
    );
}

#[test]
fn falls_back_to_the_derived_port_when_none_or_zero_is_specified() {
    for specified_port in [None, Some(0)] {
        let mut console = Vec::new();

        let port = select_callback_port_to(&mut console, specified_port, 4242);

        assert_eq!(port, 4242);
        let pid = std::process::id();
        assert_eq!(
            console_text(console),
            format!("[{pid}] Using callback port derived from the server URL: 4242\n")
        );
    }
}
