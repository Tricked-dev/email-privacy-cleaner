use email_privacy_cleaner::ruleset::{RuleLoadLimits, RulePackFormat, RulesetBuilder, SkipReason};

fn limits_with(max_regex_rules: usize) -> RuleLoadLimits {
    RuleLoadLimits {
        max_regex_rules,
        ..RuleLoadLimits::default()
    }
}

#[test]
fn regex_budget_covers_scopes_redirects_raw_rules_and_beacons_atomically() {
    let source = serde_json::json!({
        "providers": {
            "wide": {
                "urlPattern": "^https://example\\.com/[a-z]+",
                "completeProvider": true,
                "rules": ["campaign[0-9]+"],
                "rawRules": ["tracking[0-9]+"],
                "redirections": ["https://example\\.com/redirect/(.*)"]
            }
        }
    })
    .to_string();
    let mut builder = RulesetBuilder::new(limits_with(2));

    builder
        .add_source_str(
            "regex-budget",
            &source,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();

    let ruleset = builder.finish();
    let report = ruleset.load_report();
    let source_report = report
        .sources
        .iter()
        .find(|report| report.source == "regex-budget")
        .unwrap();
    assert_eq!(source_report.skipped_reason, Some(SkipReason::RegexLimit));
    assert_eq!(source_report.accepted_rules, 0);
}

#[test]
fn oversized_url_scope_is_skipped_and_reported() {
    let long_scope = format!("*://{}.example/*", "a".repeat(65 * 1024));
    let source = serde_json::json!([{
        "include": [long_scope],
        "exclude": [],
        "params": ["tracking"]
    }])
    .to_string();
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());

    builder
        .add_source_str(
            "oversized-scope",
            &source,
            Some(RulePackFormat::BraveCleanUrls),
            None,
        )
        .unwrap();

    let ruleset = builder.finish();
    let source_report = ruleset
        .load_report()
        .sources
        .iter()
        .find(|report| report.source == "oversized-scope")
        .unwrap();
    assert!(source_report.failed_regexes > 0);
    assert_eq!(source_report.accepted_rules, 0);
    assert_eq!(ruleset.stats().groups, 0);
}

#[test]
fn oversized_redirect_path_raw_and_beacon_patterns_are_not_retained() {
    let long_literal = "a".repeat(65 * 1024);
    let debounce = serde_json::json!([{
        "include": ["*://short.example/*"],
        "exclude": [],
        "action": "regex-path",
        "param": format!("^/(.*){long_literal}")
    }])
    .to_string();
    let mut debounce_builder = RulesetBuilder::new(RuleLoadLimits::default());
    debounce_builder
        .add_source_str(
            "oversized-path",
            &debounce,
            Some(RulePackFormat::BraveDebounce),
            None,
        )
        .unwrap();
    let debounce_rules = debounce_builder.finish();
    let debounce_report = debounce_rules
        .load_report()
        .sources
        .iter()
        .find(|report| report.source == "oversized-path")
        .unwrap();
    assert!(debounce_report.failed_regexes > 0);
    assert_eq!(debounce_report.accepted_rules, 0);
    assert!(debounce_rules
        .redirect_target("https://short.example/path")
        .is_none());

    let clearurls = serde_json::json!({
        "providers": {
            "raw": {
                "urlPattern": "^https://raw.example",
                "rawRules": [format!("raw[0-9]+{long_literal}")]
            }
        }
    })
    .to_string();
    let mut raw_builder = RulesetBuilder::new(RuleLoadLimits::default());
    raw_builder
        .add_source_str(
            "oversized-raw",
            &clearurls,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    let raw_rules = raw_builder.finish();
    let raw_report = raw_rules
        .load_report()
        .sources
        .iter()
        .find(|report| report.source == "oversized-raw")
        .unwrap();
    assert!(raw_report.failed_regexes > 0);
    assert_eq!(raw_rules.stats().raw_rules, 0);

    let adguard = format!("||{long_literal}.example^$image\n");
    let mut beacon_builder = RulesetBuilder::new(RuleLoadLimits::default());
    beacon_builder
        .add_source_str(
            "oversized-beacon",
            &adguard,
            Some(RulePackFormat::AdGuard),
            None,
        )
        .unwrap();
    let beacon_rules = beacon_builder.finish();
    let beacon_report = beacon_rules
        .load_report()
        .sources
        .iter()
        .find(|report| report.source == "oversized-beacon")
        .unwrap();
    assert!(beacon_report.failed_regexes > 0);
    assert_eq!(beacon_rules.stats().beacon_rules, 0);
}

#[test]
fn generated_adguard_scope_expansion_is_bounded() {
    // `^` is a compact AdGuard separator, but each separator expands into a
    // multi-byte regular-expression fragment. The source remains small while
    // its generated expression exceeds the runtime safety bound.
    let compact_expansion = "^".repeat(3_000);
    let source = format!("||example.com{compact_expansion}$image\n");
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());

    builder
        .add_source_str(
            "generated-adguard-scope",
            &source,
            Some(RulePackFormat::AdGuard),
            None,
        )
        .unwrap();

    let ruleset = builder.finish();
    assert_eq!(ruleset.stats().beacon_rules, 0);
    assert!(ruleset.skipped_patterns > 0);
}

#[test]
fn match_only_regex_sets_are_split_by_aggregate_pattern_bytes() {
    let rules = (0..160)
        .map(|index| format!("item{index}{}[0-9]+", "a".repeat(1_000)))
        .collect::<Vec<_>>();
    let source = serde_json::json!({
        "providers": {
            "chunked": {
                "urlPattern": "^https://example\\.com",
                "rules": rules
            }
        }
    })
    .to_string();
    let ruleset = RulesetBuilder::new(RuleLoadLimits::default());
    let mut builder = ruleset;
    builder
        .add_source_str(
            "aggregate-regex",
            &source,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();

    let ruleset = builder.finish();
    assert!(ruleset.stats().regex_set_chunks >= 2);
}

#[test]
fn shared_scope_counts_once_against_regex_budget() {
    let source = serde_json::json!([{
        "include": ["*://example.com/*"],
        "exclude": [],
        "params": ["one", "two", "three", "four"]
    }])
    .to_string();
    let mut builder = RulesetBuilder::new(limits_with(1));

    builder
        .add_source_str(
            "shared-brave-scope",
            &source,
            Some(RulePackFormat::BraveCleanUrls),
            None,
        )
        .unwrap();

    let ruleset = builder.finish();
    let source_report = ruleset
        .load_report()
        .sources
        .iter()
        .find(|report| report.source == "shared-brave-scope")
        .unwrap();
    assert_eq!(source_report.skipped_reason, None);
    assert_eq!(ruleset.stats().scopes, 1);
    assert_eq!(ruleset.stats().groups, 4);
}
