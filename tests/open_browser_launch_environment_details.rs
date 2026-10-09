use rust_mcp_remote::open_browser::browser_launch_environment_details;
use serde_json::json;
use std::collections::HashMap;

fn details_for(variables: &[(&str, &str)]) -> serde_json::Value {
    let environment: HashMap<String, String> = variables
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    browser_launch_environment_details(|name| environment.get(name).cloned())
}

#[test]
fn names_every_variable_in_the_order_the_typescript_gives_them() {
    let details = details_for(&[
        ("DISPLAY", ":0"),
        ("WAYLAND_DISPLAY", "wayland-0"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ("BROWSER", "firefox"),
    ]);

    assert_eq!(
        details.to_string(),
        r#"{"DISPLAY":":0","WAYLAND_DISPLAY":"wayland-0","DBUS_SESSION_BUS_ADDRESS":"set","BROWSER":"firefox"}"#
    );
}

#[test]
fn leaves_out_variables_that_are_not_set() {
    assert_eq!(details_for(&[]), json!({}));
}

#[test]
fn leaves_out_an_empty_bus_address_but_keeps_other_empty_values() {
    let details = details_for(&[("DISPLAY", ""), ("DBUS_SESSION_BUS_ADDRESS", "")]);

    assert_eq!(details, json!({ "DISPLAY": "" }));
}
