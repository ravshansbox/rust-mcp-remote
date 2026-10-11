//! `SendError`: how a transport failure is kept and classified for the proxy's sign-in retry.

use super::*;
use rust_mcp_remote::streamable_http::TransportError;

#[test]
fn keeps_unauthorized_and_http_failures_and_flattens_the_rest() {
    assert_eq!(
        SendError::from(TransportError::Unauthorized("no token".to_owned())),
        SendError::Unauthorized("no token".to_owned())
    );
    assert_eq!(
        SendError::from(TransportError::Http {
            status: 401,
            message: "refused".to_owned(),
        }),
        SendError::Http {
            status: 401,
            message: "refused".to_owned(),
        }
    );
    assert_eq!(
        SendError::from(TransportError::InsufficientScope {
            required_scope: Some("write".to_owned()),
            resource_metadata_url: None,
            error_description: None,
        }),
        SendError::Other("Insufficient scope: required \"write\"".to_owned())
    );
    assert_eq!(
        SendError::from(TransportError::Other("boom".to_owned())),
        SendError::Other("boom".to_owned())
    );
}

#[test]
fn tells_a_missing_sign_in_from_a_refused_one() {
    assert!(SendError::Unauthorized("no token".to_owned()).is_unauthorized());
    // The SDK's message check: any failure that says Unauthorized counts.
    assert!(SendError::Other("HTTP 401 Unauthorized".to_owned()).is_unauthorized());
    assert!(!SendError::Other("boom".to_owned()).is_unauthorized());

    let refused = SendError::Http {
        status: 401,
        message: "refused".to_owned(),
    };
    assert!(refused.is_rejected_after_authorizing());
    assert!(!refused.is_unauthorized());
    assert!(
        !SendError::Http {
            status: 403,
            message: "forbidden".to_owned(),
        }
        .is_rejected_after_authorizing()
    );
    assert!(!SendError::Unauthorized("no token".to_owned()).is_rejected_after_authorizing());
}
