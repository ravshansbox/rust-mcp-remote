use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub fn apply_client_authentication(
    method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    headers: &mut Vec<(String, String)>,
    params: &mut Vec<(String, String)>,
) -> Result<(), String> {
    if method == "client_secret_basic" {
        let Some(client_secret) = client_secret.filter(|secret| !secret.is_empty()) else {
            return Err("client_secret_basic authentication requires a client_secret".to_string());
        };
        let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
        set_pair(
            headers,
            "Authorization",
            &format!("Basic {credentials}"),
            true,
        );
        return Ok(());
    }

    if method == "client_secret_post" {
        set_pair(params, "client_id", client_id, false);
        if let Some(client_secret) = client_secret.filter(|secret| !secret.is_empty()) {
            set_pair(params, "client_secret", client_secret, false);
        }
        return Ok(());
    }

    if method != "none" {
        return Err(format!(
            "Unsupported client authentication method: {method}"
        ));
    }

    set_pair(params, "client_id", client_id, false);
    Ok(())
}

fn set_pair(pairs: &mut Vec<(String, String)>, name: &str, value: &str, ignore_case: bool) {
    let matches = |key: &str| {
        if ignore_case {
            key.eq_ignore_ascii_case(name)
        } else {
            key == name
        }
    };
    match pairs.iter().position(|(key, _)| matches(key)) {
        Some(index) => {
            pairs[index].1 = value.to_string();
            let mut position = 0;
            pairs.retain(|(key, _)| {
                let keep = position <= index || !matches(key);
                position += 1;
                keep
            });
        }
        None => pairs.push((name.to_string(), value.to_string())),
    }
}
