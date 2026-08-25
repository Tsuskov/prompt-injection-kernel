import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from kernel.provenance import Label, Tainted, Trust, as_trusted


def test_combine_trust_untrusted_wins():
    t = Label(Trust.TRUSTED)
    u = Label(Trust.UNTRUSTED)
    assert t.combine(u).trust is Trust.UNTRUSTED
    assert u.combine(t).trust is Trust.UNTRUSTED
    assert u.combine(u).trust is Trust.UNTRUSTED
    assert t.combine(t).trust is Trust.TRUSTED


def test_combine_confidential_ored():
    a = Label(Trust.TRUSTED, confidential=True)
    b = Label(Trust.TRUSTED, confidential=False)
    assert a.combine(b).confidential is True
    assert b.combine(a).confidential is True
    assert b.combine(b).confidential is False
    assert a.combine(a).confidential is True


def test_combine_sources_union():
    a = Label(Trust.TRUSTED, sources=frozenset({"inbox"}))
    b = Label(Trust.TRUSTED, sources=frozenset({"calendar"}))
    assert a.combine(b).sources == frozenset({"inbox", "calendar"})
    c = Label(Trust.TRUSTED, sources=frozenset())
    assert a.combine(c).sources == frozenset({"inbox"})


def test_tainted_map_applies_fn_preserves_label():
    lbl = Label(Trust.UNTRUSTED, confidential=True, sources=frozenset({"web"}))
    t = Tainted("hello", lbl)
    t2 = t.map(str.upper)
    assert t2.value == "HELLO"
    assert t2.label is lbl


def test_as_trusted():
    t = as_trusted(42)
    assert t.value == 42
    assert t.label.trust is Trust.TRUSTED
    assert t.label.confidential is False
    assert t.label.sources == frozenset()


def test_label_str_empty_sources_and_confidential():
    lbl = Label(Trust.UNTRUSTED)
    assert str(lbl) == "untrusted [-]"
    lbl2 = Label(Trust.TRUSTED, confidential=True, sources=frozenset({"inbox"}))
    assert str(lbl2) == "trusted/confidential [inbox]"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all tests passed")
