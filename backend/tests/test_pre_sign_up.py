# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_backend.auth import pre_sign_up


def event(email, source="PreSignUp_SignUp"):
    return {
        "triggerSource": source,
        "request": {"userAttributes": {"email": email}},
        "response": {},
    }


def test_allows_listed_domain(monkeypatch):
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAINS", "example.com,example.org")
    assert pre_sign_up.handler(event("A.User@Example.com"), None)["request"]["userAttributes"][
        "email"
    ]


@pytest.mark.parametrize("email", ["x@evil.com", "x@sub.example.com.evil.com", "no-at-sign", ""])
def test_rejects_other_domains(monkeypatch, email):
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAINS", "example.com")
    with pytest.raises(Exception, match="approved email domains"):
        pre_sign_up.handler(event(email), None)


def test_admin_created_users_pass(monkeypatch):
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAINS", "example.com")
    assert pre_sign_up.handler(event("x@evil.com", "PreSignUp_AdminCreateUser"), None)
