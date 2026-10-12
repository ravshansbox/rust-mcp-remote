use rust_mcp_remote::mcp_auth_config::{config_file_path, delete_config_file, write_text_file};

use crate::with_temporary_config_dir;

const HASH: &str = "delete-test";
const FILENAME: &str = "tokens.json";

#[test]
fn deleting_an_existing_file_removes_it() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "{}").expect("write file");
        delete_config_file(HASH, FILENAME);
        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn deleting_a_missing_file_does_nothing() {
    with_temporary_config_dir(|| {
        delete_config_file(HASH, FILENAME);
        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn deleting_leaves_other_files_alone() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "{}").expect("write file");
        write_text_file(HASH, "client_info.json", "{}").expect("write other file");
        write_text_file("other-hash", FILENAME, "{}").expect("write other hash file");
        delete_config_file(HASH, FILENAME);
        assert!(config_file_path(HASH, "client_info.json").exists());
        assert!(config_file_path("other-hash", FILENAME).exists());
    });
}
