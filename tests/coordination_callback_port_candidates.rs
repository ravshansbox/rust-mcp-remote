use rust_mcp_remote::coordination::{
    PORT_CANDIDATES, callback_port_candidates, no_free_callback_port_message,
};

#[test]
fn tries_eight_ports_from_the_callback_port() {
    assert_eq!(PORT_CANDIDATES, 8);
    assert_eq!(
        callback_port_candidates(3334, false),
        vec![3334, 3335, 3336, 3337, 3338, 3339, 3340, 3341]
    );
}

#[test]
fn tries_only_the_callback_port_when_strict() {
    assert_eq!(callback_port_candidates(3334, true), vec![3334]);
}

#[test]
fn stops_at_the_highest_port() {
    assert_eq!(callback_port_candidates(65534, false), vec![65534, 65535]);
}

#[test]
fn names_the_range_of_ports_tried() {
    assert_eq!(
        no_free_callback_port_message(&callback_port_candidates(3334, false)),
        "Could not find a free callback port for this server (tried 3334-3341). Close whatever is holding those ports, or pass a port as the second argument to choose one."
    );
}
