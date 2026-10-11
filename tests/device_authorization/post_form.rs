use std::sync::Arc;

use rust_mcp_remote::device_authorization::{FormRequest, FormResponse, post_form};

use crate::test_server::{reply, serve};

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[tokio::test]
async fn posts_the_encoded_params_with_the_headers_and_returns_status_and_body() {
    let (base, mut requests) =
        serve(Arc::new(|_| reply(400, &[], r#"{"error":"slow_down"}"#))).await;

    let response = post_form(
        &format!("{base}/device"),
        &FormRequest {
            headers: pairs(&[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", "Basic abc"),
            ]),
            params: pairs(&[("client_id", "cli"), ("scope", "read write&more")]),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        response,
        FormResponse {
            status: 400,
            body: r#"{"error":"slow_down"}"#.to_string(),
        }
    );

    let request = requests.try_recv().unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/device");
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(request.header("authorization"), Some("Basic abc"));
    assert_eq!(request.body, "client_id=cli&scope=read+write%26more");
}

#[tokio::test]
async fn a_connection_failure_is_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let result = post_form(
        &format!("http://{address}/token"),
        &FormRequest {
            headers: Vec::new(),
            params: pairs(&[("grant_type", "x")]),
        },
    )
    .await;
    assert!(result.is_err());
}
