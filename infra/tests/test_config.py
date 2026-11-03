# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import aws_cdk as cdk
import pytest

from phish_infra.config import load_config, normalize_domains


def config_for(**context):
    return load_config(cdk.App(context=context).node)


def test_defaults():
    cfg = config_for()
    # Neutral: a customer deploying the sample tags resources with their own -c owner.
    assert cfg.owner == "phish-triage-owner"
    assert cfg.environment == "dev"
    assert cfg.invite_code is False
    assert cfg.sign_up_mode == "app"
    assert cfg.retention_days == 90
    assert cfg.allowed_email_domains == ()
    assert cfg.agent_registry is False
    assert cfg.scan_concurrency == 25
    assert cfg.orchestrator_model == "us.anthropic.claude-opus-5-5"
    assert cfg.specialist_model == "global.anthropic.claude-sonnet-5-5"
    assert cfg.harness_max_tokens == 8192
    assert cfg.app_name == "phish"
    assert cfg.removal_policy == cdk.RemovalPolicy.DESTROY


def test_prod_retains():
    assert config_for(environment="prod").removal_policy == cdk.RemovalPolicy.RETAIN


@pytest.mark.parametrize("raw", ["true", True, "True"])
def test_invite_code_bool_parsing(raw):
    assert config_for(inviteCode=raw).invite_code is True


def test_sign_up_mode_rejects_unknown():
    with pytest.raises(ValueError, match="signUpMode"):
        config_for(signUpMode="open")


def test_invite_code_is_app_mode_only():
    # Native Cognito self sign-up has no invite step; refusing at synth beats a silently open pool.
    with pytest.raises(ValueError, match="inviteCode"):
        config_for(signUpMode="cognito", inviteCode=True)


@pytest.mark.parametrize("value", [0, 3651, "x"])
def test_retention_days_bounds(value):
    with pytest.raises(ValueError, match="retentionDays"):
        config_for(retentionDays=value)


@pytest.mark.parametrize("mode", ["registry", "direct", "parallel"])
def test_the_removed_specialist_mode_fails_with_the_replacement(mode):
    # Not mapped silently: registry is now opt-in and direct no longer exists.
    with pytest.raises(ValueError, match=r"specialistMode was removed.*-c agentRegistry=true"):
        config_for(specialistMode=mode)


@pytest.mark.parametrize("raw,expected", [("true", True), (True, True), ("false", False)])
def test_agent_registry_flag(raw, expected):
    assert config_for(agentRegistry=raw).agent_registry is expected


@pytest.mark.parametrize("value", [1, 1001, "abc"])
def test_scan_concurrency_bounds(value):
    # SQS event source maximumConcurrency accepts 2 to 1000.
    with pytest.raises(ValueError, match="scanConcurrency"):
        config_for(scanConcurrency=value)


@pytest.mark.parametrize("value", [1000, 3000])
def test_harness_max_tokens_floor(value):
    # The final turn carries thinking plus a report of up to 450 words; below 4096 the
    # verdict is cut off (stop_reason=max_tokens) and the scan fails.
    with pytest.raises(ValueError, match="harnessMaxTokens"):
        config_for(harnessMaxTokens=value)


def test_harness_max_tokens_accepts_the_floor():
    assert config_for(harnessMaxTokens=4096).harness_max_tokens == 4096


def test_harness_max_tokens_rejects_garbage():
    with pytest.raises(ValueError, match="harnessMaxTokens"):
        config_for(harnessMaxTokens="lots")


def test_normalize_domains_from_string_and_list():
    assert normalize_domains(" Example.com, amazon.com ,") == ("example.com", "amazon.com")
    assert normalize_domains(["A.org", "a.org"]) == ("a.org",)
    assert normalize_domains("") == ()
    assert normalize_domains("*") == ()


def test_normalize_domains_idn():
    assert normalize_domains("bücher.de") == ("xn--bcher-kva.de",)


def test_normalize_domains_rejects_garbage():
    with pytest.raises(ValueError, match="allowedEmailDomains"):
        normalize_domains("not a domain")


def test_ses_from_address_defaults_to_cognito_email():
    assert config_for().ses_from_address is None


def test_ses_from_address_is_validated():
    assert (
        config_for(sesFromAddress=" Alerts@Example.com ").ses_from_address == "Alerts@Example.com"
    )
    with pytest.raises(ValueError, match="sesFromAddress"):
        config_for(sesFromAddress="not-an-email")


CERT = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555"


def test_custom_domain_defaults_off():
    cfg = config_for()
    assert cfg.domain_name is None and cfg.certificate_arn is None


def test_custom_domain_needs_both_flags():
    with pytest.raises(ValueError, match="domainName and certificateArn"):
        config_for(domainName="phish.example.com")
    with pytest.raises(ValueError, match="domainName and certificateArn"):
        config_for(certificateArn=CERT)


def test_custom_domain_is_validated():
    cfg = config_for(domainName="Phish.Example.com", certificateArn=CERT)
    assert cfg.domain_name == "phish.example.com" and cfg.certificate_arn == CERT
    with pytest.raises(ValueError, match="certificateArn"):
        config_for(
            domainName="phish.example.com", certificateArn=CERT.replace("us-east-1", "us-west-2")
        )
    with pytest.raises(ValueError, match="domainName"):
        config_for(domainName="not a domain", certificateArn=CERT)


def test_mfa_and_cognito_plan_defaults():
    cfg = config_for()
    assert cfg.mfa == "optional" and cfg.cognito_plan == "essentials"
    assert config_for(mfa="REQUIRED").mfa == "required"
    assert config_for(cognitoPlan="Plus").cognito_plan == "plus"


def test_mfa_and_cognito_plan_reject_unknown():
    with pytest.raises(ValueError, match="mfa"):
        config_for(mfa="off")
    with pytest.raises(ValueError, match="cognitoPlan"):
        config_for(cognitoPlan="lite")


def test_owner_flag_overrides_the_neutral_default():
    assert config_for(owner="alice").owner == "alice"


def test_cdk_json_does_not_pin_an_owner():
    import json
    from pathlib import Path

    context = json.loads((Path(__file__).resolve().parents[1] / "cdk.json").read_text())["context"]
    assert "owner" not in context


def test_orchestrator_effort_is_validated():
    assert config_for(orchestratorEffort="LOW").orchestrator_effort == "low"
    assert config_for(orchestratorEffort="high").orchestrator_effort == "high"
    with pytest.raises(ValueError, match="orchestratorEffort"):
        config_for(orchestratorEffort="max")


def test_orchestrator_effort_defaults_to_medium_with_or_without_the_registry():
    # low broke the turn-1 JSON in 2 of 5 scans once the orchestrator called the specialists.
    assert config_for().orchestrator_effort == "medium"
    assert config_for(agentRegistry=True).orchestrator_effort == "medium"


def test_orchestrator_effort_override_beats_the_default():
    # -c orchestratorEffort=low, and -c orchestratorEffort= (empty) to send no override.
    assert config_for(orchestratorEffort="low").orchestrator_effort == "low"
    assert config_for(orchestratorEffort="").orchestrator_effort == ""


def test_cdk_json_ships_effort_medium():
    import json
    from pathlib import Path

    context = json.loads((Path(__file__).resolve().parents[1] / "cdk.json").read_text())["context"]
    assert context["orchestratorEffort"] == "medium"
    assert context["agentRegistry"] is False and "specialistMode" not in context
    assert config_for(**context).orchestrator_effort == "medium"


def test_episodic_memory_on_by_default():
    assert config_for().episodic_memory is True


@pytest.mark.parametrize("raw", ["false", False, "False"])
def test_episodic_memory_opt_out(raw):
    assert config_for(episodicMemory=raw).episodic_memory is False


def test_cache_ttl_defaults_and_overrides():
    assert config_for().rdap_cache_ttl_hours == 168
    assert config_for().web_search_cache_ttl_hours == 24
    cfg = config_for(rdapCacheTtlHours=24, webSearchCacheTtlHours=2)
    assert (cfg.rdap_cache_ttl_hours, cfg.web_search_cache_ttl_hours) == (24, 2)


@pytest.mark.parametrize("flag", ["rdapCacheTtlHours", "webSearchCacheTtlHours"])
@pytest.mark.parametrize("value", [0, 8761, "abc"])
def test_cache_ttl_rejects_out_of_range(flag, value):
    with pytest.raises(ValueError):
        config_for(**{flag: value})


def test_app_name_default_keeps_the_original_stack_names():
    cfg = config_for()
    assert cfg.stack_prefix == "PhishTriageAgentic"


def test_app_name_prefixes_the_stack_names():
    cfg = config_for(appName="Demo2")
    assert cfg.app_name == "demo2"
    assert cfg.stack_prefix == "Demo2TriageAgentic"


@pytest.mark.parametrize("bad", ["", "a", "2fast", "with-dash", "under_score", "x" * 13])
def test_app_name_rejects_names_that_cannot_prefix_every_resource(bad):
    with pytest.raises(ValueError, match="appName"):
        config_for(appName=bad)
