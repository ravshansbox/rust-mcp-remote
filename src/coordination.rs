pub const PORT_CANDIDATES: u16 = 8;

pub fn callback_port_candidates(callback_port: u16, strict_port: bool) -> Vec<u16> {
    if strict_port {
        return vec![callback_port];
    }
    (0..PORT_CANDIDATES)
        .filter_map(|offset| callback_port.checked_add(offset))
        .collect()
}

pub fn no_free_callback_port_message(candidates: &[u16]) -> String {
    let first = candidates.first().copied().unwrap_or_default();
    let last = candidates.last().copied().unwrap_or_default();
    format!(
        "Could not find a free callback port for this server (tried {first}-{last}). Close whatever is holding those ports, or pass a port as the second argument to choose one."
    )
}
