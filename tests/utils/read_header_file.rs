use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rust_mcp_remote::utils::read_header_file_to;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

fn header_file(name: &str, contents: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "mcp-remote-headers-{}-{nanos}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("directory");
    let path = directory.join(name);
    std::fs::write(&path, contents).expect("write");
    path
}

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn reads_one_header_per_line_and_skips_blanks_and_comments() {
    let path = header_file(
        "headers.txt",
        "# credentials\r\nAuthorization: Bearer secret\r\n\r\n   \nX-Tenant:acme\n",
    );
    let mut console = Vec::new();

    let headers = read_header_file_to(&mut console, path.to_str().expect("path")).expect("headers");

    assert_eq!(
        headers,
        pairs(&[("Authorization", "Bearer secret"), ("X-Tenant", "acme")])
    );
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Loaded 2 header(s) from {path}\n",
            pid = std::process::id(),
            path = path.display()
        )
    );
}

#[test]
fn a_later_line_overrides_an_earlier_one_in_its_original_place() {
    let path = header_file("headers.txt", "A: 1\nB: 2\nA: 3\n");

    let headers =
        read_header_file_to(&mut Vec::new(), path.to_str().expect("path")).expect("headers");

    assert_eq!(headers, pairs(&[("A", "3"), ("B", "2")]));
}

#[test]
fn warns_by_line_number_about_lines_that_are_not_headers() {
    let path = header_file("headers.txt", "A: 1\nnot a header secret\nB: 2\n");
    let mut console = Vec::new();

    let headers = read_header_file_to(&mut console, path.to_str().expect("path")).expect("headers");

    assert_eq!(headers, pairs(&[("A", "1"), ("B", "2")]));
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: ignoring line 2 of {path}, which is not in Name:Value form\n[{pid}] Loaded 2 header(s) from {path}\n",
            pid = std::process::id(),
            path = path.display()
        )
    );
}

#[test]
fn an_unreadable_file_is_an_error_naming_the_file() {
    let path = std::env::temp_dir().join("mcp-remote-headers-that-does-not-exist.txt");
    let mut console = Vec::new();

    let error =
        read_header_file_to(&mut console, path.to_str().expect("path")).expect_err("missing file");

    assert!(
        error.starts_with(&format!(
            "Could not read the header file {}: ",
            path.display()
        )),
        "{error}"
    );
    assert!(console.is_empty());
}
