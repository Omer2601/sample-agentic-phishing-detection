# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import logging
from datetime import UTC, datetime

from botocore.exceptions import ClientError, EndpointConnectionError

from phish_backend.worker import scan_memory
from phish_contracts.models import Verdict

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
MEMORY_ID = "phish_scan_memory_dev-abcdef1234"


def verdict(**overrides):
    base = {
        "verdict": "phishing",
        "risk_score": 92,
        "confidence": "high",
        "action": "block",
        "summary": "Fake Microsoft login posts credentials off-domain.\nSecond line.",
        "report_markdown": "# r",
    }
    return Verdict.model_validate({**base, **overrides})


def denied(op):
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)


class FakeMemory:
    def __init__(self, records=(), error=None, failed=()):
        self.records = list(records)
        self.error = error
        self.failed = list(failed)
        self.retrieved = []
        self.created = []

    def retrieve_memory_records(self, **kwargs):
        self.retrieved.append(kwargs)
        if self.error:
            raise self.error
        return {
            "memoryRecordSummaries": [
                {
                    "memoryRecordId": f"r{i}",
                    "content": {"text": text},
                    "score": 0.9,
                    "metadata": {"scan_id": {"stringValue": f"past-{i}"}},
                }
                for i, text in enumerate(self.records)
            ]
        }

    def batch_create_memory_records(self, **kwargs):
        self.created.append(kwargs)
        if self.error:
            raise self.error
        return {"successfulRecords": [], "failedRecords": self.failed}


def test_summary_is_one_short_defanged_line():
    text = scan_memory.summarize("https://login.evil.example/a", verdict())
    assert text == (
        "hxxps://login[.]evil[.]example/a | verdict=phishing | risk=92 | "
        "reason: Fake Microsoft login posts credentials off-domain."
    )
    assert "\n" not in text


def test_summary_caps_reason_and_strips_markup():
    long = "<b>" + "word " * 200
    text = scan_memory.summarize("https://a.example/", verdict(summary=long))
    reason = text.split("reason: ", 1)[1]
    assert len(reason) <= scan_memory.REASON_CHARS
    assert "<" not in text and ">" not in text


def test_recall_asks_for_three_similar_scans_by_defanged_url():
    fake = FakeMemory(records=["a", "b", "c"])
    found = scan_memory.recall(fake, MEMORY_ID, "https://evil.example/")
    assert [p.summary for p in found] == ["a", "b", "c"]
    assert [p.scan_id for p in found] == ["past-0", "past-1", "past-2"]
    (call,) = fake.retrieved
    assert call["memoryId"] == MEMORY_ID
    assert call["namespace"] == scan_memory.NAMESPACE
    assert call["searchCriteria"] == {"searchQuery": "hxxps://evil[.]example/", "topK": 3}


def test_recall_keeps_at_most_three_non_empty_records():
    fake = FakeMemory(records=["a", "", "b", "c", "d"])
    found = scan_memory.recall(fake, MEMORY_ID, "https://evil.example/")
    assert [p.summary for p in found] == ["a", "b", "c"]


def test_recall_disabled_without_memory_id():
    fake = FakeMemory(records=["a"])
    assert scan_memory.recall(fake, "", "https://evil.example/") == []
    assert fake.retrieved == []


def test_recall_failure_returns_nothing_and_logs(caplog):
    for error in (denied("RetrieveMemoryRecords"), EndpointConnectionError(endpoint_url="x")):
        fake = FakeMemory(error=error)
        with caplog.at_level(logging.WARNING):
            assert scan_memory.recall(fake, MEMORY_ID, "https://evil.example/") == []
    assert "episodic memory read failed" in caplog.text


def test_recall_ignores_malformed_response():
    class Odd(FakeMemory):
        def retrieve_memory_records(self, **kwargs):
            return {"memoryRecordSummaries": [{"content": {}}, {"nope": 1}]}

    assert scan_memory.recall(Odd(), MEMORY_ID, "https://evil.example/") == []


def test_remember_writes_one_idempotent_record():
    fake = FakeMemory()
    assert scan_memory.remember(fake, MEMORY_ID, "scan-1", "https://evil.example/", verdict(), NOW)
    (call,) = fake.created
    assert call["memoryId"] == MEMORY_ID
    assert call["clientToken"] == "scan-1"
    (record,) = call["records"]
    assert record["requestIdentifier"] == "scan-1"
    assert record["namespaces"] == [scan_memory.NAMESPACE]
    assert record["timestamp"] == NOW
    assert record["content"]["text"].startswith("hxxps://evil[.]example/ | verdict=phishing")
    assert record["metadata"] == {
        "verdict": {"stringValue": "phishing"},
        "scan_id": {"stringValue": "scan-1"},
    }


def test_remember_disabled_without_memory_id():
    fake = FakeMemory()
    assert not scan_memory.remember(fake, "", "s", "https://a.example/", verdict(), NOW)
    assert fake.created == []


def test_remember_failure_is_logged_not_raised(caplog):
    with caplog.at_level(logging.WARNING):
        ok = scan_memory.remember(
            FakeMemory(error=denied("BatchCreateMemoryRecords")),
            MEMORY_ID,
            "s",
            "https://a.example/",
            verdict(),
            NOW,
        )
        rejected = scan_memory.remember(
            FakeMemory(failed=[{"requestIdentifier": "s", "errorMessage": "bad"}]),
            MEMORY_ID,
            "s",
            "https://a.example/",
            verdict(),
            NOW,
        )
    assert ok is False and rejected is False
    assert "episodic memory write failed" in caplog.text


def test_record_without_scan_id_metadata_has_no_scan_id():
    class Old(FakeMemory):
        def retrieve_memory_records(self, **kwargs):
            return {"memoryRecordSummaries": [{"content": {"text": "a"}}]}

    (past,) = scan_memory.recall(Old(), MEMORY_ID, "https://evil.example/")
    assert past.summary == "a" and past.scan_id is None


def test_stored_record_never_names_the_owner():
    # Memory is shared by every user of a deployment, so the record holds no owner id,
    # principal ARN or email: only the defanged URL, verdict, risk, reason and scan id.
    fake = FakeMemory()
    owner = "arn:aws:sts::123456789012:assumed-role/ProxyRole:user-a"
    scan_memory.remember(fake, MEMORY_ID, "scan-1", "https://a.example/", verdict(), NOW)
    stored = str(fake.created)
    for leak in (owner, "user-a", "ProxyRole", "@", "owner"):
        assert leak not in stored
