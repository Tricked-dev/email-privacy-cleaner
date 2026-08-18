//! Characterization tests for the ruleset loading/finalization contract.
//!
//! These tests specify the loader, limits, reporting, and sender-store
//! contracts in `RULESET_REFACTOR_PLAN.md`. They exercise the public facade
//! and its immutable compiled store.

use std::collections::BTreeMap;
use std::sync::Arc;

use email_privacy_cleaner::config::{
    CleanerConfig, RulePackFormat, RulePackUsage, RuleResourceLimits, SenderPolicy,
};
use email_privacy_cleaner::ruleset::{Ruleset, SkipReason};
use email_privacy_cleaner::Result;

const TOML_WITHOUT_PACKS: &str = "mode = \"enforce\"";

fn pack(provider: &str, parameter: &str) -> String {
    format!(
        r#"{{"providers":{{"{provider}":{{"urlPattern":"^https://{provider}\\.example","rules":["{parameter}"]}}}}}}"#
    )
}

fn fixture_loader<'a>(
    fixtures: &'a BTreeMap<&'a str, String>,
    calls: &'a mut Vec<String>,
) -> impl FnMut(&str) -> Result<Vec<u8>> + 'a {
    move |source| {
        calls.push(source.to_owned());
        fixtures
            .get(source)
            .cloned()
            .map(String::into_bytes)
            .ok_or_else(|| email_privacy_cleaner::CleanerError::Config(format!("missing {source}")))
    }
}

#[test]
fn toml_parsing_does_not_fetch_or_compile_external_sources_until_finalize() {
    let source = "fixture://toml-pack";
    let provider = "toml_unfinalized";
    let mut config = CleanerConfig::from_toml_str_unfinalized(
        r#"
            mode = "enforce"
            rule_pack_urls = ["fixture://toml-pack"]
        "#,
    )
    .unwrap();

    let fixtures = BTreeMap::from([(source, pack(provider, "toml_id"))]);
    let mut calls = Vec::new();

    // Parsing may validate TOML, but it must not touch the configured source
    // or publish an external compiled provider.
    assert!(config
        .ruleset()
        .detect_provider("https://toml_unfinalized.example/path")
        .is_none());
    assert!(calls.is_empty());

    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    assert!(config
        .ruleset()
        .detect_provider("https://toml_unfinalized.example/path")
        .is_some());
    assert!(report.sources.iter().any(|source_report| {
        source_report.source == source && source_report.skipped_reason.is_none()
    }));
}

#[test]
fn from_toml_str_retains_auto_finalizing_compatibility() {
    let config = CleanerConfig::from_toml_str(
        r#"
            mode = "enforce"
            extra_tracking_params = ["compatibility_id"]
        "#,
    )
    .unwrap();

    assert!(config.is_tracking_param("compatibility_id"));
}

#[test]
fn compatibility_finalization_reuses_ruleset_without_reloading_sources() {
    let source = "fixture://compat-idempotent";
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();
    config
        .rule_pack_sources
        .push(email_privacy_cleaner::config::RulePackSource {
            source: source.into(),
            format: Some(RulePackFormat::ClearUrls),
            usage: None,
        });

    let fixtures = BTreeMap::from([(source, pack("compat_idempotent", "compat_id"))]);
    let mut calls = Vec::new();
    config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();
    let first = config.ruleset();

    // `from_toml_str` finalized the compatibility path. A later public
    // finalization with unchanged inputs must reuse the compiled store
    // instead of fetching configured sources again.
    config.finalize();
    let second = config.ruleset();

    assert_eq!(calls, vec![source]);
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn partial_rule_limits_fill_omitted_values_from_defaults() {
    let config = CleanerConfig::parse_toml_str(
        r#"
            [rule_limits]
            max_rule_pack_bytes = 17
        "#,
    )
    .unwrap();

    assert_eq!(config.rule_limits.max_rule_pack_bytes, 17);
    assert_eq!(
        config.rule_limits.max_total_rule_pack_bytes,
        RuleResourceLimits::default().max_total_rule_pack_bytes
    );
}

#[test]
fn structured_sources_preserve_format_and_usage_metadata() {
    let source = "fixture://structured-pack";
    let mut config = CleanerConfig::from_toml_str_unfinalized(TOML_WITHOUT_PACKS).unwrap();
    config
        .rule_pack_sources
        .push(email_privacy_cleaner::config::RulePackSource {
            source: source.into(),
            format: Some(RulePackFormat::ClearUrls),
            usage: Some(RulePackUsage::MailBeacon),
        });

    let fixtures = BTreeMap::from([(source, pack("structured", "structured_id"))]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    assert_eq!(
        report
            .sources
            .iter()
            .find(|source_report| source_report.source == source)
            .unwrap()
            .format,
        Some(RulePackFormat::ClearUrls)
    );
}

#[test]
fn duplicate_sources_are_loaded_once() {
    let source = "fixture://duplicate-pack";
    let mut config = CleanerConfig::from_toml_str_unfinalized(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.extend([source.into(), source.into()]);

    let fixtures = BTreeMap::from([(source, pack("duplicate", "duplicate_id"))]);
    let mut calls = Vec::new();
    config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    assert!(config
        .ruleset()
        .detect_provider("https://duplicate.example/path")
        .is_some());
}

#[test]
fn loader_failures_are_reported_as_io_skips() {
    let source = "fixture://missing-pack";
    let mut config = CleanerConfig::from_toml_str_unfinalized(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.push(source.into());
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&BTreeMap::new(), &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    assert_eq!(
        report
            .sources
            .iter()
            .find(|source_report| source_report.source == source)
            .unwrap()
            .skipped_reason,
        Some(SkipReason::Io)
    );
}

#[test]
fn parse_failures_are_reported_once_without_partial_acceptance() {
    let source = "fixture://invalid-pack";
    let mut config = CleanerConfig::from_toml_str_unfinalized(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.push(source.into());
    let fixtures = BTreeMap::from([(source, "[".to_string())]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    let source_report = report
        .sources
        .iter()
        .find(|source_report| source_report.source == source)
        .unwrap();
    assert_eq!(source_report.skipped_reason, Some(SkipReason::Parse));
}

#[test]
fn auto_format_rejects_malformed_json_shape() {
    let source = "fixture://malformed-auto";
    let mut config = CleanerConfig::from_toml_str_unfinalized(TOML_WITHOUT_PACKS).unwrap();
    config
        .rule_pack_sources
        .push(email_privacy_cleaner::config::RulePackSource {
            source: source.into(),
            format: None,
            usage: None,
        });
    let fixtures = BTreeMap::from([(source, "[".to_string())]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    let source_report = report
        .sources
        .iter()
        .find(|source_report| source_report.source == source)
        .unwrap();
    assert_eq!(
        source_report.skipped_reason,
        Some(SkipReason::UnknownFormat)
    );
}

#[test]
fn config_and_cli_packs_are_applied_before_one_finalization() {
    let config_source = "fixture://config-pack";
    let cli_source = "fixture://cli-pack";
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();

    // `rule_packs` is the existing public list used by --rule-pack.  Both
    // configured and CLI additions must be merged before the single freeze.
    config.rule_pack_urls.push(config_source.into());
    config.rule_packs.push(cli_source.into());

    let fixtures = BTreeMap::from([
        (config_source, pack("config_source", "config_id")),
        (cli_source, pack("cli_source", "cli_id")),
    ]);
    let mut calls = Vec::new();
    config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![cli_source, config_source]);
    assert!(config
        .ruleset()
        .detect_provider("https://config_source.example/path")
        .is_some());
    assert!(config
        .ruleset()
        .detect_provider("https://cli_source.example/path")
        .is_some());
}

#[test]
fn source_byte_limit_rejects_the_whole_local_source_atomically() {
    let source = "fixture://over-byte";
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.push(source.into());
    config.rule_limits = RuleResourceLimits {
        max_rule_pack_bytes: 8,
        ..RuleResourceLimits::default()
    };

    let fixtures = BTreeMap::from([(source, pack("over_byte", "must_not_survive"))]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![source]);
    assert!(config
        .ruleset()
        .detect_provider("https://over_byte.example/path")
        .is_none());
    assert!(report
        .sources
        .iter()
        .any(|source_report| { source_report.skipped_reason.is_some() }));
}

#[test]
fn total_byte_limit_rejects_a_source_without_partial_acceptance() {
    let first = "fixture://total-first";
    let second = "fixture://total-second";
    let first_pack = pack("total_first", "first_id");
    let second_pack = pack("total_second", "second_id");
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.extend([first.into(), second.into()]);
    config.rule_limits = RuleResourceLimits {
        max_rule_pack_bytes: first_pack.len().max(second_pack.len()),
        max_total_rule_pack_bytes: first_pack.len(),
        ..RuleResourceLimits::default()
    };

    let fixtures = BTreeMap::from([(first, first_pack), (second, second_pack)]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();
    assert_eq!(calls, vec![first, second]);
    assert!(config
        .ruleset()
        .detect_provider("https://total_first.example/path")
        .is_some());
    assert!(config
        .ruleset()
        .detect_provider("https://total_second.example/path")
        .is_none());
    assert!(report
        .sources
        .iter()
        .any(|source_report| { source_report.skipped_reason.is_some() }));
}

#[test]
fn source_count_limit_rejects_sources_after_the_budget_without_partial_acceptance() {
    let first = "fixture://count-first";
    let second = "fixture://count-second";
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.extend([first.into(), second.into()]);
    config.rule_limits = RuleResourceLimits {
        max_rule_pack_sources: 1,
        ..RuleResourceLimits::default()
    };

    let fixtures = BTreeMap::from([
        (first, pack("count_first", "first_id")),
        (second, pack("count_second", "second_id")),
    ]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();

    assert_eq!(calls, vec![first]);
    assert!(config
        .ruleset()
        .detect_provider("https://count_first.example/path")
        .is_some());
    assert!(config
        .ruleset()
        .detect_provider("https://count_second.example/path")
        .is_none());
    assert!(report
        .sources
        .iter()
        .any(|source_report| { source_report.skipped_reason.is_some() }));
}

#[test]
fn load_reports_retain_only_bounded_diagnostic_samples() {
    let source = "fixture://diagnostics";
    let invalid_rules = (0..64)
        .map(|index| format!("(?=unsupported_{index})"))
        .collect::<Vec<_>>();
    let fixture = serde_json::json!({
        "providers": {
            "diagnostics": {
                "urlPattern": "^https://diagnostics\\.example",
                "rules": invalid_rules,
            }
        }
    })
    .to_string();
    let mut config = CleanerConfig::from_toml_str(TOML_WITHOUT_PACKS).unwrap();
    config.rule_packs.push(source.into());
    config.rule_limits = RuleResourceLimits {
        max_diagnostic_samples: 3,
        ..RuleResourceLimits::default()
    };

    let fixtures = BTreeMap::from([(source, fixture)]);
    let mut calls = Vec::new();
    let report = config
        .finalize_with_loader(&mut fixture_loader(&fixtures, &mut calls))
        .unwrap();
    let source_report = report
        .sources
        .iter()
        .find(|source_report| source_report.source == source)
        .unwrap();

    assert!(source_report.failed_regexes >= 64);
    assert!(source_report.unsupported_samples.len() <= 3);
}

#[test]
fn effective_sender_configs_share_the_compiled_store() {
    let mut config = CleanerConfig::default();
    config.sender_policies.push(SenderPolicy {
        match_domains: vec!["sender.example".into()],
        clean_html: Some(false),
        ..SenderPolicy::default()
    });
    config.finalize();

    let global_store = config.ruleset();
    let (effective, _) = config.effective_for_sender(Some("mail.sender.example"));
    let sender_store = effective.ruleset();

    assert!(Arc::ptr_eq(&global_store, &sender_store));
}

#[test]
fn compiled_ruleset_is_safe_to_match_concurrently() {
    let ruleset = Arc::new(Ruleset::builtin());
    let handles = (0..8)
        .map(|_| {
            let ruleset = Arc::clone(&ruleset);
            std::thread::spawn(move || {
                for _ in 0..128 {
                    assert!(ruleset.should_remove_parameter(
                        "https://example.test/path?utm_source=x",
                        "utm_source=x",
                        true,
                        false,
                    ));
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().unwrap();
    }
}
