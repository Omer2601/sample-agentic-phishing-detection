# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_backend.batch.csv_parse import parse_url_csv

FIVE = [
    "https://a.example/",
    "http://b.example/x",
    "https://c.example/?q=1",
    "http://d.example/",
    "https://e.example/",
]


def test_header_row_is_skipped():
    parsed = parse_url_csv(("url\n" + "\n".join(FIVE) + "\n").encode(), 200)
    assert parsed.urls == FIVE


def test_no_header():
    assert parse_url_csv("\n".join(FIVE).encode(), 200).urls == FIVE


def test_crlf_and_bom():
    data = ("\ufeffURL\r\n" + "\r\n".join(FIVE) + "\r\n").encode()
    assert parse_url_csv(data, 200).urls == FIVE


def test_extra_columns_blank_rows_and_duplicates():
    data = b"https://a.example/,label\n\n  \nhttps://a.example/\nhttps://b.example/,x,y\n"
    parsed = parse_url_csv(data, 200)
    assert parsed.urls == ["https://a.example/", "https://b.example/"]
    assert parsed.duplicates == 1


def test_invalid_rows_are_reported_with_row_numbers():
    parsed = parse_url_csv(b"https://ok.example/\nftp://no\nhttp://127.0.0.1/\n", 200)
    assert parsed.urls == ["https://ok.example/"]
    assert [r["row"] for r in parsed.invalid] == [2, 3]
    assert parsed.invalid_count == 2
    assert "http:// or https://" in parsed.invalid[0]["reason"]


def test_over_cap_is_flagged():
    data = "\n".join(f"https://h{i}.example/" for i in range(201)).encode()
    parsed = parse_url_csv(data, 200)
    assert parsed.over_cap is True


def test_quoted_url_with_comma():
    parsed = parse_url_csv(b'"https://a.example/p?x=1,2"\n', 200)
    assert parsed.urls == ["https://a.example/p?x=1,2"]


def test_non_utf8_rejected():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_url_csv(b"\xff\xfe\x00h", 200)


def test_malformed_csv_raises_a_clear_value_error():
    body = b'"' + b"a" * 200_000 + b'"\n'
    with pytest.raises(ValueError, match="not a readable CSV"):
        parse_url_csv(body, 10)
