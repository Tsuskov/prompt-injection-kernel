import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from kernel.provenance import Label, Tainted, Trust
from kernel.quarantine import quarantine_email
from kernel.tools import Email


def test_from_addr_header_label():
    email = Email(from_addr="sender@example.com", subject="Test", body="Hello world.")
    result = quarantine_email(email, "test")
    assert result["from_addr"].label.trust == Trust.UNTRUSTED
    assert result["from_addr"].label.confidential is False
    assert result["from_addr"].label.sources == frozenset({"test:header"})
    assert result["from_addr"].value == "sender@example.com"


def test_subject_body_label():
    email = Email(from_addr="sender@example.com", subject="Test Subject", body="Hello world.")
    result = quarantine_email(email, "test")
    assert result["subject"].label.trust == Trust.UNTRUSTED
    assert result["subject"].label.confidential is True
    assert result["subject"].label.sources == frozenset({"test:body"})


def test_summary_body_label():
    email = Email(from_addr="sender@example.com", subject="Test", body="Hello world.")
    result = quarantine_email(email, "test")
    assert result["summary"].label.trust == Trust.UNTRUSTED
    assert result["summary"].label.confidential is True
    assert result["summary"].label.sources == frozenset({"test:body"})


def test_contents_body_label():
    email = Email(from_addr="sender@example.com", subject="Test", body="Hello world.")
    result = quarantine_email(email, "test")
    assert result["contents"].label.trust == Trust.UNTRUSTED
    assert result["contents"].label.confidential is True
    assert result["contents"].label.sources == frozenset({"test:body"})


def test_injected_addr_body_label():
    email = Email(from_addr="sender@example.com", subject="Test", body="Contact me at hidden@example.com")
    result = quarantine_email(email, "test")
    assert result["injected_addr"].label.trust == Trust.UNTRUSTED
    assert result["injected_addr"].label.confidential is True
    assert result["injected_addr"].label.sources == frozenset({"test:body"})


def test_summary_first_sentence_only():
    email = Email(from_addr="a@b.com", subject="s", body="First sentence. Second sentence. Third.")
    result = quarantine_email(email, "src")
    assert result["summary"].value == "First sentence."


def test_summary_capped_at_160_chars():
    long_sentence = "A" * 200
    email = Email(from_addr="a@b.com", subject="s", body=long_sentence)
    result = quarantine_email(email, "src")
    assert len(result["summary"].value) <= 160
    assert result["summary"].value == long_sentence[:160]


def test_summary_first_sentence_and_cap():
    long_first = "X" * 200 + " "
    email = Email(from_addr="a@b.com", subject="s", body=long_first + "Second.")
    result = quarantine_email(email, "src")
    assert result["summary"].value == "X" * 160


def test_injected_addr_extracted_from_body():
    email = Email(from_addr="sender@example.com", subject="Test", body="Mail me at smuggled@test.com")
    result = quarantine_email(email, "mail")
    assert result["injected_addr"].value == "smuggled@test.com"
    assert result["injected_addr"].label.sources == frozenset({"mail:body"})


def test_injected_addr_empty_when_no_email_in_body():
    email = Email(from_addr="sender@example.com", subject="Test", body="No email here")
    result = quarantine_email(email, "mail")
    assert result["injected_addr"].value == ""


def test_injected_addr_not_header_source():
    email = Email(from_addr="sender@example.com", subject="Test", body="Contact hidden@test.com")
    result = quarantine_email(email, "mail")
    assert result["injected_addr"].label.sources != frozenset({"mail:header"})
    assert result["injected_addr"].label.sources == frozenset({"mail:body"})


def test_all_fields_untrusted():
    email = Email(from_addr="a@b.com", subject="s", body="body with hidden@test.com")
    result = quarantine_email(email, "x")
    assert result["from_addr"].label.trust == Trust.UNTRUSTED
    assert result["subject"].label.trust == Trust.UNTRUSTED
    assert result["summary"].label.trust == Trust.UNTRUSTED
    assert result["contents"].label.trust == Trust.UNTRUSTED
    assert result["injected_addr"].label.trust == Trust.UNTRUSTED


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all tests passed")
