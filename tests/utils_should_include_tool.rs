use rust_mcp_remote::utils::should_include_tool;

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn single_wildcard_pattern_ignores_matching_tools() {
    let ignore_patterns = patterns(&["create*"]);
    assert!(!should_include_tool(&ignore_patterns, "createTask"));
    assert!(should_include_tool(&ignore_patterns, "getTask"));
}

#[test]
fn multiple_wildcard_patterns_ignore_matching_tools() {
    let ignore_patterns = patterns(&["create*", "put*"]);
    assert!(!should_include_tool(&ignore_patterns, "createTask"));
    assert!(!should_include_tool(&ignore_patterns, "putTask"));
    assert!(should_include_tool(&ignore_patterns, "infoTask"));
}

#[test]
fn suffix_wildcard_pattern_ignores_matching_tools() {
    let ignore_patterns = patterns(&["*account"]);
    assert!(!should_include_tool(&ignore_patterns, "getAccount"));
    assert!(!should_include_tool(&ignore_patterns, "putAccount"));
    assert!(!should_include_tool(&ignore_patterns, "account"));
}

#[test]
fn empty_ignore_patterns_include_all_tools() {
    assert!(should_include_tool(&[], "anyTool"));
}

#[test]
fn non_matching_patterns_include_tools() {
    let ignore_patterns = patterns(&["delete*", "remove*"]);
    assert!(should_include_tool(&ignore_patterns, "createTask"));
}

#[test]
fn exact_match_without_wildcards() {
    let ignore_patterns = patterns(&["exactTool", "anotherTool"]);
    assert!(!should_include_tool(&ignore_patterns, "exactTool"));
    assert!(should_include_tool(&ignore_patterns, "differentTool"));
    assert!(should_include_tool(&ignore_patterns, "exactTools"));
    assert!(should_include_tool(&ignore_patterns, "myexactTool"));
}

#[test]
fn matching_is_case_insensitive() {
    assert!(!should_include_tool(&patterns(&["CREATE*"]), "createTask"));
    assert!(!should_include_tool(&patterns(&["ä*"]), "Äx"));
}

#[test]
fn wildcards_can_sit_anywhere_and_match_nothing() {
    assert!(!should_include_tool(&patterns(&["get*Task"]), "getBigTask"));
    assert!(!should_include_tool(&patterns(&["a**b"]), "ab"));
    assert!(!should_include_tool(&patterns(&["*"]), ""));
    assert!(should_include_tool(&patterns(&["get*Task"]), "getTasks"));
}

#[test]
fn other_characters_match_only_themselves() {
    assert!(should_include_tool(&patterns(&["get.*"]), "getXaccount"));
    assert!(!should_include_tool(&patterns(&["get.*"]), "get.foo"));
    assert!(!should_include_tool(&patterns(&["a+b"]), "a+b"));
    assert!(should_include_tool(&patterns(&["a+b"]), "aab"));
}

#[test]
fn wildcards_do_not_match_line_terminators() {
    let ignore_patterns = patterns(&["a*b"]);
    assert!(should_include_tool(&ignore_patterns, "a\nb"));
    assert!(should_include_tool(&ignore_patterns, "a\rb"));
    assert!(should_include_tool(&ignore_patterns, "a\u{2028}b"));
    assert!(should_include_tool(&ignore_patterns, "a\u{2029}b"));
    assert!(should_include_tool(&patterns(&["tool"]), "Tool\n"));
}

#[test]
fn case_folding_follows_javascript_rules() {
    assert!(should_include_tool(&patterns(&["ſ"]), "s"));
    assert!(should_include_tool(&patterns(&["ß"]), "SS"));
}
