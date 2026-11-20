import pytest

from mixerscope.schema.guards import InstanceDataError, assert_no_instance_data, find_instance_data

# Synthetic tokens shaped like instance data (not taken from any real case).
HEX64 = "a" * 32 + "b" * 32
BECH32 = "bc1q" + "q" * 38
BASE58 = "1" + "A" * 33
UNIQID = "0123456789abcd.12345678"


@pytest.mark.parametrize(
    "text, kind",
    [
        (HEX64, "64-hex hash / TXID"),
        (f"TXID: {HEX64}", "64-hex hash / TXID"),
        (BECH32, "bech32 address"),
        (BASE58, "base58 BTC address"),
        ("0x" + "c" * 40, "EVM address"),
        (UNIQID, "PHP uniqid order ID"),
        ("2026-07-22T09:41:00", "ISO-8601 timestamp"),
    ],
)
def test_detects_instance_like_values(text, kind):
    hit = find_instance_data(text)
    assert hit is not None and hit[0] == kind


@pytest.mark.parametrize(
    "text",
    [
        "ci_session",
        "/Home/check_transaction",
        "Letter_<orderid>.txt",
        "mixeroyubx5g5yxaucsxcd767vn2lnujuuz2dh53quwabukhrok2ekid.onion",
        "Transaction has been completed with TXID: <64-hex payout txid>",
        "Max-Age=86400",
        "session<14hex>.<digits>",
        "bc1[a-hj-np-z0-9]{38,58}",
    ],
)
def test_invariant_strings_pass(text):
    assert find_instance_data(text) is None


def test_walks_nested_structures():
    with pytest.raises(InstanceDataError) as ei:
        assert_no_instance_data({"a": ["fine", {"b": f"see {BECH32}"}]}, "root")
    assert ei.value.path == "root.a[1].b"
    assert "case findings" in str(ei.value)
