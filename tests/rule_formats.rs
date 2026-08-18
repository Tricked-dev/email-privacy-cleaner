use email_privacy_cleaner::config::{CleanerConfig, RulePackSource};
use email_privacy_cleaner::redirect::unwrap_redirect_url;
use email_privacy_cleaner::ruleset::{
    RedirectOrigin, RuleLoadLimits, RulePackFormat, Ruleset, RulesetBuilder,
};
use email_privacy_cleaner::validate::RejectReason;
use std::sync::atomic::{AtomicUsize, Ordering};
use url::Url;

static NEXT_PACK_ID: AtomicUsize = AtomicUsize::new(0);

fn removes(ruleset: &Ruleset, url: &str, segment: &str) -> bool {
    ruleset.should_remove_parameter(url, segment, true, true)
}

#[test]
fn brave_clean_urls_preserves_raw_case_sensitive_and_encoded_keys() {
    let ruleset = Ruleset::from_brave_clean_urls_str(
        r#"[
            {
                "include": ["*://example.com/*"],
                "exclude": [],
                "params": ["UTM_Source", "encoded%5B0%5D", "encoded[0]"]
            }
        ]"#,
    )
    .unwrap();

    let url = "https://example.com/path?UTM_Source=x&encoded%5B0%5D=y&encoded[0]=z";
    assert!(removes(&ruleset, url, "UTM_Source=x"));
    assert!(removes(&ruleset, url, "encoded%5B0%5D=y"));
    assert!(removes(&ruleset, url, "encoded[0]=z"));
    assert!(!removes(&ruleset, url, "utm_source=x"));
    assert!(!removes(&ruleset, url, "UTM_Source"));
}

#[test]
fn adguard_removeparam_matches_exact_and_name_value_regex() {
    let ruleset = Ruleset::from_adguard_str(
        "||example.com^$removeparam=utm_source\n||example.com^$removeparam=/^campaign=[a-z]+$/\n",
    )
    .unwrap();
    let url = "https://example.com/path?utm_source=x&campaign=spring&campaign=SPRING";

    assert!(removes(&ruleset, url, "utm_source=x"));
    assert!(removes(&ruleset, url, "campaign=spring"));
    assert!(!removes(&ruleset, url, "campaign=SPRING"));
    assert!(removes(&ruleset, url, "utm_source"));
}

#[test]
fn adguard_exception_only_negates_its_action() {
    let ruleset = Ruleset::from_adguard_str(
        "||example.com^$removeparam=utm_source\n||example.com^$removeparam=campaign\n@@||example.com^$removeparam=utm_source\n",
    )
    .unwrap();
    let url = "https://example.com/path?utm_source=x&campaign=spring";

    assert!(!removes(&ruleset, url, "utm_source=x"));
    assert!(removes(&ruleset, url, "campaign=spring"));
}

#[test]
fn brave_debounce_path_template_requires_matching_captures() {
    let ruleset = Ruleset::from_brave_debounce_str(
        r#"[
            {
                "include": ["*://short.example/*"],
                "exclude": [],
                "action": "regex-path-template",
                "param": "^/([^/]+)/([^/]+)$",
                "redirect_url_template": "https://$1.example/$2"
            }
        ]"#,
    )
    .unwrap();

    let url = Url::parse("https://short.example/www/landing").unwrap();
    assert_eq!(
        ruleset.redirect_target(url.as_str()).as_deref(),
        Some("https://www.example/landing")
    );
    assert!(ruleset
        .redirect_target("https://short.example/not-enough")
        .is_none());
}

#[test]
fn brave_debounce_path_template_rejects_placeholders_outside_one_through_nine() {
    let ruleset = Ruleset::from_brave_debounce_str(
        r#"[
            {
                "include": ["*://short.example/*"],
                "exclude": [],
                "action": "regex-path-template",
                "param": "^/([^/]+)$",
                "redirect_url_template": "https://$10.example/$1"
            }
        ]"#,
    )
    .unwrap();

    assert_eq!(ruleset.stats().redirect_rules, 0);
    assert_eq!(ruleset.load_report().sources[0].unsupported_rules, 1);
    assert!(ruleset
        .redirect_target("https://short.example/www")
        .is_none());
}

#[test]
fn brave_debounce_path_template_requires_exact_capture_correspondence() {
    for template in ["https://$1.example/$3", "https://$1.example/$1"] {
        let source = format!(
            r#"[
                {{
                    "include": ["*://short.example/*"],
                    "exclude": [],
                    "action": "regex-path-template",
                    "param": "^/([^/]+)/([^/]+)$",
                    "redirect_url_template": "{template}"
                }}
            ]"#
        );
        let ruleset = Ruleset::from_brave_debounce_str(&source).unwrap();

        assert_eq!(ruleset.stats().redirect_rules, 0);
        assert_eq!(ruleset.load_report().sources[0].unsupported_rules, 1);
        assert!(ruleset
            .redirect_target("https://short.example/www/landing")
            .is_none());
    }
}

#[test]
fn brave_debounce_path_template_rejects_malformed_placeholder_syntax() {
    for template in ["https://$1.example/$", "https://$1.example/${1}"] {
        let source = format!(
            r#"[
                {{
                    "include": ["*://short.example/*"],
                    "exclude": [],
                    "action": "regex-path-template",
                    "param": "^/([^/]+)$",
                    "redirect_url_template": "{template}"
                }}
            ]"#
        );
        let ruleset = Ruleset::from_brave_debounce_str(&source).unwrap();

        assert_eq!(ruleset.stats().redirect_rules, 0);
        assert_eq!(ruleset.load_report().sources[0].unsupported_rules, 1);
        assert!(ruleset
            .redirect_target("https://short.example/www/landing")
            .is_none());
    }
}

#[test]
fn brave_pref_rules_are_skipped_and_reported() {
    let ruleset = Ruleset::from_brave_debounce_str(
        r#"[
            {
                "include": ["*://amp.example/*"],
                "exclude": [],
                "pref": "brave.de_amp.enabled",
                "action": "regex-path",
                "param": "^/(.*)$",
                "prepend_scheme": "https"
            }
        ]"#,
    )
    .unwrap();

    assert!(ruleset
        .redirect_target("https://amp.example/destination.example/path")
        .is_none());
    assert!(ruleset
        .load_report()
        .sources
        .iter()
        .flat_map(|source| source.unsupported_samples.iter())
        .any(|sample| sample.contains("pref")));
}

#[test]
fn redirects_use_deterministic_source_order() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    for (source, parameter) in [("first", "first"), ("second", "second")] {
        let pack = format!(
            r#"[{{"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"{parameter}"}}]"#
        );
        builder
            .add_source_str(source, &pack, Some(RulePackFormat::BraveDebounce), None)
            .unwrap();
    }

    // The source order is the precedence contract; the first source wins.
    assert_eq!(
        builder
        .finish()
            .redirect_target("https://short.example/x?first=https%3A%2F%2Ffirst.example&second=https%3A%2F%2Fsecond.example")
            .as_deref(),
        Some("https%3A%2F%2Ffirst.example")
    );
}

#[test]
fn redirects_preserve_source_order_when_rule_counts_differ() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    let first = r#"[
        {"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"first_a"},
        {"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"first_b"}
    ]"#;
    let second = r#"[
        {"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"second"}
    ]"#;
    builder
        .add_source_str("first", first, Some(RulePackFormat::BraveDebounce), None)
        .unwrap();
    builder
        .add_source_str("second", second, Some(RulePackFormat::BraveDebounce), None)
        .unwrap();

    assert_eq!(
        builder
            .finish()
            .redirect_target(
                "https://short.example/x?first_b=https%3A%2F%2Ffirst.example&second=https%3A%2F%2Fsecond.example"
            )
            .as_deref(),
        Some("https%3A%2F%2Ffirst.example")
    );
}

#[test]
fn semantic_dedup_drops_provenance_but_keeps_source_semantics() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    let clearurls = |provider: &str| {
        format!(
            r#"{{"providers":{{"{provider}":{{"urlPattern":"^https://example\\.com","rules":["same"]}}}}}}"#
        )
    };
    builder
        .add_source_str(
            "one",
            &clearurls("one"),
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "two",
            &clearurls("two"),
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "brave",
            r#"[{"include":["*://example.com/*"],"exclude":[],"params":["BraveOnly"]}]"#,
            Some(RulePackFormat::BraveCleanUrls),
            None,
        )
        .unwrap();
    let ruleset = builder.finish();

    assert_eq!(ruleset.stats().groups, 2);
    assert!(removes(&ruleset, "https://example.com/path?same", "same"));
    assert!(!removes(
        &ruleset,
        "https://example.com/path?BraveOnly",
        "BraveOnly"
    ));
    assert!(removes(
        &ruleset,
        "https://example.com/path?BraveOnly=x",
        "BraveOnly=x"
    ));
}

#[test]
fn disabled_providers_are_removed_before_deduplication() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    let pack = |provider: &str| {
        format!(
            r#"{{"providers":{{"{provider}":{{"urlPattern":"^https://example\\.com","rules":["same"]}}}}}}"#
        )
    };
    builder
        .add_source_str(
            "disabled",
            &pack("disabled"),
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "enabled",
            &pack("enabled"),
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder.disable_providers(&["disabled".into()]);
    let ruleset = builder.finish();

    assert_eq!(ruleset.stats().groups, 1);
    assert!(removes(
        &ruleset,
        "https://example.com/path?same=x",
        "same=x"
    ));
}

#[test]
fn regex_matchers_are_compiled_in_bounded_chunks() {
    let rules = (0..257)
        .map(|index| format!(r#"item{index}[a-z]+"#))
        .collect::<Vec<_>>();
    let json = serde_json::json!({
        "providers": {"many": {
            "urlPattern": "^https://example\\.com",
            "rules": rules,
        }}
    })
    .to_string();
    let ruleset = Ruleset::from_clearurls_str(&json).unwrap();

    assert!(ruleset.stats().regex_set_chunks >= 2);
    assert!(removes(
        &ruleset,
        "https://example.com/path?item256abc=x",
        "item256abc=x"
    ));
}

#[test]
fn unrestricted_literal_dot_star_is_classified_as_a_prefix() {
    let ruleset = Ruleset::from_clearurls_str(
        r#"{"providers":{"globalRules":{"urlPattern":"^https?://","rules":["utm_.*"]}}}"#,
    )
    .unwrap();

    assert_eq!(ruleset.stats().prefix_param_rules, 1);
    assert_eq!(ruleset.stats().regex_param_rules, 0);
    assert!(removes(
        &ruleset,
        "https://example.com/path?utm_source=x",
        "utm_source=x"
    ));
}

#[test]
fn raw_rules_are_explicit_api_only() {
    let ruleset = Ruleset::from_clearurls_str(
        r#"{"providers":{"raw":{"urlPattern":"^https://example\\.com","rules":[],"rawRules":["utm_[a-z]+"]}}}"#,
    )
    .unwrap();
    let url = "https://example.com/path?utm_source=x";

    assert!(!removes(&ruleset, url, "utm_source=x"));
    assert_eq!(
        ruleset.apply_raw_rules(url),
        ("https://example.com/path?=x".into(), true)
    );
}

#[test]
fn adguard_scope_and_exception_are_action_scoped() {
    let ruleset = Ruleset::from_adguard_str(
        "||example.com^$removeparam=utm_source,domain=example.com\n@@||example.com^$removeparam=utm_source,domain=example.com\n||example.com^$removeparam=campaign,domain=example.com\n",
    )
    .unwrap();

    assert!(!removes(
        &ruleset,
        "https://example.com/path?utm_source=x",
        "utm_source=x"
    ));
    assert!(removes(
        &ruleset,
        "https://example.com/path?campaign=x",
        "campaign=x"
    ));
    assert!(!removes(
        &ruleset,
        "https://other.example/path?utm_source=x",
        "utm_source=x"
    ));
}

#[test]
fn adguard_empty_target_preserves_domain_scope_for_parameters_exceptions_and_images() {
    let ruleset = Ruleset::from_adguard_str(
        "*$removeparam=utm_source,domain=one.example\n\
         *$removeparam=campaign\n\
         @@*$removeparam=campaign,domain=one.example\n\
         *$image,domain=one.example\n",
    )
    .unwrap();

    assert!(removes(
        &ruleset,
        "https://one.example/path?utm_source=x",
        "utm_source=x"
    ));
    assert!(!removes(
        &ruleset,
        "https://two.example/path?utm_source=x",
        "utm_source=x"
    ));
    assert!(!removes(
        &ruleset,
        "https://one.example/path?campaign=x",
        "campaign=x"
    ));
    assert!(removes(
        &ruleset,
        "https://two.example/path?campaign=x",
        "campaign=x"
    ));
    assert!(ruleset.is_beacon_url("https://one.example/pixel", Some("one.example")));
    assert!(!ruleset.is_beacon_url("https://two.example/pixel", Some("two.example")));
}

#[test]
fn adguard_image_exceptions_are_skipped_instead_of_blocking() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    builder
        .add_source_str(
            "image-exceptions",
            "@@||tracker.example^$image\n@@||mail.example^\n",
            Some(RulePackFormat::AdGuard),
            Some(email_privacy_cleaner::ruleset::RulePackUsage::MailBeacon),
        )
        .unwrap();
    let ruleset = builder.finish();

    assert!(!ruleset.is_beacon_url("https://tracker.example/pixel", None));
    assert!(!ruleset.is_beacon_url("https://mail.example/pixel", None));
    let report = ruleset
        .load_report()
        .sources
        .iter()
        .find(|source| source.source == "image-exceptions")
        .unwrap();
    assert_eq!(report.accepted_rules, 0);
    assert_eq!(report.unsupported_rules, 2);
}

#[test]
fn adguard_mixed_removeparam_image_does_not_clean_anchor_urls() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    builder
        .add_source_str(
            "mixed-image-removeparam",
            "||example.com^$removeparam=utm_source,image\n",
            Some(RulePackFormat::AdGuard),
            None,
        )
        .unwrap();
    let ruleset = builder.finish();

    // A mixed action/content rule cannot be limited to image/CSS contexts by
    // the parameter-cleaning API, so it must never affect ordinary anchors.
    assert!(!removes(
        &ruleset,
        "https://example.com/article?utm_source=newsletter",
        "utm_source=newsletter"
    ));
    assert!(!ruleset.is_beacon_url("https://example.com/pixel", None));

    let report = ruleset
        .load_report()
        .sources
        .iter()
        .find(|source| source.source == "mixed-image-removeparam")
        .unwrap();
    assert_eq!(report.accepted_rules, 0);
    assert_eq!(report.unsupported_rules, 1);
}

#[test]
fn adguard_exact_and_regex_exceptions_only_negate_the_same_matcher_kind() {
    let exact_positive_regex_exception = Ruleset::from_adguard_str(
        "||example.com^$removeparam=utm_source\n@@||example.com^$removeparam=/^utm_source=.*$/\n",
    )
    .unwrap();
    let regex_positive_exact_exception = Ruleset::from_adguard_str(
        "||example.com^$removeparam=/^utm_source=.*$/\n@@||example.com^$removeparam=utm_source\n",
    )
    .unwrap();
    let regex_positive_regex_exception = Ruleset::from_adguard_str(
        "||example.com^$removeparam=/^utm_source=.*$/\n@@||example.com^$removeparam=/^utm_source=.*$/\n",
    )
    .unwrap();

    let url = "https://example.com/path?utm_source=x";
    assert!(removes(
        &exact_positive_regex_exception,
        url,
        "utm_source=x"
    ));
    assert!(removes(
        &regex_positive_exact_exception,
        url,
        "utm_source=x"
    ));
    assert!(!removes(
        &regex_positive_regex_exception,
        url,
        "utm_source=x"
    ));
}

#[test]
fn malformed_clearurls_exception_rejects_the_whole_source() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    assert!(builder
        .add_source_str(
            "malformed-clearurls",
            r#"{"providers":{"provider":{"urlPattern":"^https://example\\.com","rules":["utm_source"],"exceptions":["["]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .is_err());
    let ruleset = builder.finish();

    assert_eq!(ruleset.stats().groups, 0);
    let report = ruleset
        .load_report()
        .sources
        .iter()
        .find(|source| source.source == "malformed-clearurls")
        .unwrap();
    assert_eq!(
        report.skipped_reason,
        Some(email_privacy_cleaner::ruleset::SkipReason::Parse)
    );
}

#[test]
fn adguard_multi_domain_scope_is_indexed_for_every_domain() {
    let ruleset =
        Ruleset::from_adguard_str("*$removeparam=utm_source,domain=one.example|two.example\n")
            .unwrap();

    assert!(removes(
        &ruleset,
        "https://one.example/path?utm_source=x",
        "utm_source=x"
    ));
    assert!(removes(
        &ruleset,
        "https://two.example/path?utm_source=x",
        "utm_source=x"
    ));
    assert!(!removes(
        &ruleset,
        "https://three.example/path?utm_source=x",
        "utm_source=x"
    ));

    // Both domain buckets point at the same scoped action rather than
    // retaining a copy of the parameter matcher per domain.
    assert_eq!(ruleset.stats().groups, 1);
    assert_eq!(ruleset.stats().domain_index_keys, 2);
}

#[test]
fn beacon_domain_anchor_is_not_an_arbitrary_substring_match() {
    let ruleset = Ruleset::from_adguard_str("||example.com^$image\n").unwrap();

    assert!(ruleset.is_beacon_url("https://example.com/pixel", Some("example.com")));
    assert!(ruleset.is_beacon_url("https://sub.example.com/pixel", Some("sub.example.com")));
    assert!(!ruleset.is_beacon_url("https://notexample.com/pixel", Some("notexample.com")));
    assert!(!ruleset.is_beacon_url(
        "https://proxy.example/path?value=notexample.com",
        Some("proxy.example")
    ));
    assert!(!ruleset.is_beacon_url(
        "https://proxy.example/path/example.com/pixel",
        Some("proxy.example")
    ));

    // Keep raw-source matching for mail-provider proxy URLs whose embedded
    // destination is percent-encoded.
    assert!(ruleset.is_beacon_url(
        "https://proxy.example/pixel?url=https%3A%2F%2Fexample.com%2Fpixel",
        Some("proxy.example")
    ));
}

#[test]
fn wildcard_brave_host_is_suffix_indexed_without_false_candidates() {
    let ruleset = Ruleset::from_brave_clean_urls_str(
        r#"[{"include":["*://*.example.com/*"],"exclude":[],"params":["tracking"]}]"#,
    )
    .unwrap();

    let matching_url = Url::parse("https://mail.example.com/path?tracking=1").unwrap();
    let matching_context = ruleset.context_for(matching_url.as_str(), &matching_url);
    assert_eq!(matching_context.candidate_group_count(), 1);
    assert!(removes(&ruleset, matching_url.as_str(), "tracking=1"));

    let unrelated_url = Url::parse("https://unrelated.test/path?tracking=1").unwrap();
    let unrelated_context = ruleset.context_for(unrelated_url.as_str(), &unrelated_url);
    assert_eq!(unrelated_context.candidate_group_count(), 0);
    assert!(!removes(&ruleset, unrelated_url.as_str(), "tracking=1"));
    assert_eq!(ruleset.stats().domain_index_keys, 1);
}

#[test]
fn complete_provider_is_one_beacon_and_matches_encoded_proxy_source() {
    let ruleset = Ruleset::from_clearurls_str(
        r#"{"providers":{"pixel":{"urlPattern":"^https?://(?:[a-z0-9-]+\\.)*pixel\\.example","completeProvider":true}}}"#,
    )
    .unwrap();

    assert_eq!(ruleset.stats().beacon_rules, 1);
    assert!(ruleset.is_beacon_url("https://pixel.example/pixel", None));
    assert!(ruleset.is_beacon_url(
        "https://proxy.example/pixel?url=https%3A%2F%2Fpixel.example%2Fpixel",
        Some("proxy.example")
    ));
}

#[test]
fn clearurls_exception_does_not_suppress_other_format_actions() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    builder
        .add_source_str(
            "clearurls",
            r#"{"providers":{"globalRules":{"urlPattern":"^https://example\\.com","rules":["utm_source"]},"provider":{"urlPattern":"^https://example\\.com","rules":["provider_id"],"exceptions":["keep"]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "brave",
            r#"[{"include":["*://example.com/*"],"exclude":[],"params":["brave_id"]}]"#,
            Some(RulePackFormat::BraveCleanUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "adguard",
            "||example.com^$removeparam=adguard_id",
            Some(RulePackFormat::AdGuard),
            None,
        )
        .unwrap();
    let ruleset = builder.finish();
    let url = "https://example.com/path?utm_source=x&provider_id=x&brave_id=x&adguard_id=x&keep=1";

    assert!(removes(&ruleset, url, "utm_source=x"));
    assert!(!removes(&ruleset, url, "provider_id=x"));
    assert!(removes(&ruleset, url, "brave_id=x"));
    assert!(removes(&ruleset, url, "adguard_id=x"));
}

#[test]
fn clearurls_exceptions_preserve_shared_actions_from_other_providers() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    builder
        .add_source_str(
            "clearurls-one",
            r#"{"providers":{"one":{"urlPattern":"^https://example\\.com","rules":["shared","one_only"],"exceptions":["keep-one"]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "clearurls-two",
            r#"{"providers":{"two":{"urlPattern":"^https://example\\.com","rules":["shared","two_only"],"exceptions":["keep-two"]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    let ruleset = builder.finish();

    let keep_one = "https://example.com/path?keep-one=1";
    assert!(removes(&ruleset, keep_one, "shared=x"));
    assert!(!removes(&ruleset, keep_one, "one_only=x"));
    assert!(removes(&ruleset, keep_one, "two_only=x"));

    let keep_both = "https://example.com/path?keep-one=1&keep-two=1";
    assert!(!removes(&ruleset, keep_both, "shared=x"));
}

#[test]
fn disabled_clearurls_provider_is_removed_before_shared_action_exception_scope() {
    let mut builder = RulesetBuilder::new(RuleLoadLimits::default());
    builder
        .add_source_str(
            "clearurls-disabled",
            r#"{"providers":{"disabled":{"urlPattern":"^https://example\\.com","rules":["shared"],"exceptions":["keep"]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder
        .add_source_str(
            "clearurls-enabled",
            r#"{"providers":{"enabled":{"urlPattern":"^https://example\\.com","rules":["shared"]}}}"#,
            Some(RulePackFormat::ClearUrls),
            None,
        )
        .unwrap();
    builder.disable_providers(&["disabled".into()]);
    let ruleset = builder.finish();

    assert!(removes(
        &ruleset,
        "https://example.com/path?keep=1",
        "shared=x"
    ));
}

#[test]
fn adguard_removeparam_exception_can_negate_all_removeparam_actions() {
    let ruleset = Ruleset::from_adguard_str(
        "||example.com^$removeparam=utm_source\n@@||example.com^$removeparam\n",
    )
    .unwrap();

    assert!(!removes(
        &ruleset,
        "https://example.com/path?utm_source=x",
        "utm_source=x"
    ));
}

#[test]
fn adguard_match_case_applies_to_the_target_scope() {
    let ruleset = Ruleset::from_adguard_str(
        "|https://example.com/Exact^$removeparam=utm_source,match-case\n",
    )
    .unwrap();

    assert!(removes(
        &ruleset,
        "https://example.com/Exact?utm_source=x",
        "utm_source=x"
    ));
    assert!(!removes(
        &ruleset,
        "https://example.com/exact?utm_source=x",
        "utm_source=x"
    ));
}

#[test]
fn brave_redirect_ambiguity_does_not_rewrite() {
    let ruleset = Ruleset::from_brave_debounce_str(
        r#"[{"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"url"}]"#,
    )
    .unwrap();
    assert!(ruleset
        .redirect_target(
            "https://short.example/x?url=https%3A%2F%2Fone.example&url=https%3A%2F%2Ftwo.example"
        )
        .is_none());
}

#[test]
fn redirect_targets_retain_source_origin() {
    let brave = Ruleset::from_brave_debounce_str(
        r#"[{"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"url"}]"#,
    )
    .unwrap();
    let brave_target = brave
        .redirect_target_with_origin(
            "https://short.example/x?url=https%3A%2F%2Fdestination.example%2Flanding",
        )
        .unwrap();
    assert_eq!(brave_target.origin, RedirectOrigin::Brave);

    let clearurls = Ruleset::from_clearurls_str(
        r#"{"providers":{"legacy":{"urlPattern":"^https://legacy\\.example/","redirections":["^https://legacy\\.example/redirect\\?url=([^&]+)"]}}}"#,
    )
    .unwrap();
    let clearurls_target = clearurls
        .redirect_target_with_origin(
            "https://legacy.example/redirect?url=https%3A%2F%2Fdestination.example%2Flanding",
        )
        .unwrap();
    assert_eq!(clearurls_target.origin, RedirectOrigin::Legacy);
}

#[test]
fn brave_non_registrable_cross_host_redirect_is_rejected() {
    let path = write_pack(
        r#"[{"include":["*://short.example/*"],"exclude":[],"action":"redirect","param":"url"}]"#,
    );
    let mut config = CleanerConfig::default();
    config.rule_pack_sources = vec![RulePackSource {
        source: path.clone(),
        format: Some(RulePackFormat::BraveDebounce),
        usage: None,
    }];
    config.finalize();
    let _ = std::fs::remove_file(path);

    let input = Url::parse("https://short.example/x?url=https%3A%2F%2Fcom%2Flanding").unwrap();
    let result = unwrap_redirect_url(&input, &config);
    assert!(!result.unwrapped);
    assert_eq!(result.rejected, Some(RejectReason::BraveDestinationScope));
}

#[test]
fn brave_documented_cross_site_template_unwraps() {
    let path = write_pack(
        r#"[{"include":["*://y2u.be/*"],"exclude":[],"action":"regex-path-template","param":"^/(.+)$","redirect_url_template":"https://www.youtube.com/watch?v=$1"}]"#,
    );
    let mut config = CleanerConfig::default();
    config.rule_pack_sources = vec![RulePackSource {
        source: path.clone(),
        format: Some(RulePackFormat::BraveDebounce),
        usage: None,
    }];
    config.finalize();
    let _ = std::fs::remove_file(path);

    let input = Url::parse("https://y2u.be/dQw4w9WgXcQ").unwrap();
    let result = unwrap_redirect_url(&input, &config);
    assert!(result.unwrapped);
    assert_eq!(
        result.url.as_str(),
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    );
}

#[test]
fn brave_same_host_redirect_is_rejected() {
    let path = write_pack(
        r#"[{"include":["*://short.example.com/*"],"exclude":[],"action":"redirect","param":"url"}]"#,
    );
    let mut config = CleanerConfig::default();
    config.rule_pack_sources = vec![RulePackSource {
        source: path.clone(),
        format: Some(RulePackFormat::BraveDebounce),
        usage: None,
    }];
    config.finalize();
    let _ = std::fs::remove_file(path);

    let input =
        Url::parse("https://short.example.com/x?url=https%3A%2F%2Fshort.example.com%2Fdestination")
            .unwrap();
    let result = unwrap_redirect_url(&input, &config);
    assert!(!result.unwrapped);
    assert_eq!(result.rejected, Some(RejectReason::BraveDestinationScope));
}

#[test]
fn brave_sibling_subdomain_redirect_is_rejected() {
    let path = write_pack(
        r#"[{"include":["*://click.example.com/*"],"exclude":[],"action":"redirect","param":"url"}]"#,
    );
    let mut config = CleanerConfig::default();
    config.rule_pack_sources = vec![RulePackSource {
        source: path.clone(),
        format: Some(RulePackFormat::BraveDebounce),
        usage: None,
    }];
    config.finalize();
    let _ = std::fs::remove_file(path);

    let input = Url::parse(
        "https://click.example.com/x?url=https%3A%2F%2Flanding.example.com%2Fdestination",
    )
    .unwrap();
    let result = unwrap_redirect_url(&input, &config);
    assert!(!result.unwrapped);
    assert_eq!(result.rejected, Some(RejectReason::BraveDestinationScope));
}

#[test]
fn ruleset_default_remains_empty_for_public_api_compatibility() {
    let ruleset = Ruleset::default();
    assert_eq!(ruleset.stats(), &Default::default());
    assert!(!removes(
        &ruleset,
        "https://example.com/path?utm_source=news",
        "utm_source=news"
    ));
}

#[test]
fn legacy_cross_host_redirect_keeps_existing_behavior() {
    let path = write_pack(
        r#"{"providers":{"legacy":{"urlPattern":"^https://legacy\\.example/","redirections":["^https://legacy\\.example/redirect\\?url=([^&]+)"]}}}"#,
    );
    let mut config = CleanerConfig::default();
    config.rule_pack_sources = vec![RulePackSource {
        source: path.clone(),
        format: Some(RulePackFormat::ClearUrls),
        usage: None,
    }];
    config.finalize();
    let _ = std::fs::remove_file(path);

    let input = Url::parse(
        "https://legacy.example/redirect?url=https%3A%2F%2Fdestination.example%2Flanding",
    )
    .unwrap();
    let result = unwrap_redirect_url(&input, &config);
    assert!(result.unwrapped);
    assert_eq!(result.url.as_str(), "https://destination.example/landing");
}

#[test]
fn bare_param_api_remains_compatible_without_changing_cleaning() {
    let ruleset = Ruleset::from_brave_clean_urls_str(
        r#"[{"include":["*://example.com/*"],"exclude":[],"params":["tracker"]}]"#,
    )
    .unwrap();
    let url = "https://example.com/path?tracker";

    assert!(ruleset.param_is_tracking(url, "tracker", true, true));
    assert!(!ruleset.should_remove_parameter(url, "tracker", true, true));
}

fn write_pack(contents: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "epc-rule-format-{}-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_PACK_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).unwrap();
    path.to_string_lossy().into_owned()
}
