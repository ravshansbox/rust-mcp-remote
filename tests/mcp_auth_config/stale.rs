use std::time::{Duration, SystemTime};

use rust_mcp_remote::mcp_auth_config::{
    config_file_path, delete_stale_config_files, write_text_file,
};

use crate::with_temporary_config_dir;

const HASH: &str = "stale-test";
const PREFIX: &str = "code_verifier_";
const MAX_AGE: Duration = Duration::from_secs(600);

fn write_file_aged(server_url_hash: &str, filename: &str, age: Duration) {
    write_text_file(server_url_hash, filename, "verifier").expect("write file");
    std::fs::File::options()
        .write(true)
        .open(config_file_path(server_url_hash, filename))
        .expect("open file")
        .set_modified(SystemTime::now() - age)
        .expect("set modified time");
}

#[test]
fn removes_matching_files_older_than_max_age() {
    with_temporary_config_dir(|| {
        write_file_aged(HASH, "code_verifier_old.txt", Duration::from_secs(3600));
        delete_stale_config_files(HASH, PREFIX, MAX_AGE);
        assert!(!config_file_path(HASH, "code_verifier_old.txt").exists());
    });
}

#[test]
fn keeps_matching_files_newer_than_max_age() {
    with_temporary_config_dir(|| {
        write_file_aged(HASH, "code_verifier_new.txt", Duration::from_secs(60));
        delete_stale_config_files(HASH, PREFIX, MAX_AGE);
        assert!(config_file_path(HASH, "code_verifier_new.txt").exists());
    });
}

#[test]
fn keeps_old_files_with_another_prefix_or_hash() {
    with_temporary_config_dir(|| {
        let old = Duration::from_secs(3600);
        write_file_aged(HASH, "tokens.json", old);
        write_file_aged("other-hash", "code_verifier_old.txt", old);
        delete_stale_config_files(HASH, PREFIX, MAX_AGE);
        assert!(config_file_path(HASH, "tokens.json").exists());
        assert!(config_file_path("other-hash", "code_verifier_old.txt").exists());
    });
}

#[test]
fn does_nothing_when_the_config_dir_is_missing() {
    with_temporary_config_dir(|| {
        delete_stale_config_files(HASH, PREFIX, MAX_AGE);
        assert!(!rust_mcp_remote::mcp_auth_config::config_dir().exists());
    });
}
