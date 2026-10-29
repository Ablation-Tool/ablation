import pytest

from ablation.analyzers.gencfg import validate_message
from ablation.analyzers.junos_target import JunosTargetProfile


def _message(major=0x89, operation=3, key_length=0x98):
    data = bytearray(0x11C)
    data[0:2] = major.to_bytes(2, "big")
    data[2:4] = (4).to_bytes(2, "big")
    data[4:8] = operation.to_bytes(4, "big")
    data[12:16] = key_length.to_bytes(4, "big")
    data[32:34] = (4).to_bytes(2, "big")
    data[34:36] = (7).to_bytes(2, "big")
    return bytes(data)


def test_target_profile():
    profile = JunosTargetProfile.from_name()
    assert profile.data["abi"] == "o32"
    assert profile.data["isa"] == "mips64r2"
    assert profile.data["analysis"]["string_resolver"] == "got_aware_mips"


def test_validate_vrf_group_message():
    result = validate_message(_message())
    assert result["valid"]
    assert result["variant"] == 0x89
    assert result["fields"]["group_id"] == 7


def test_validate_short_vrf_key_and_operation():
    result = validate_message(_message(operation=9, key_length=8))
    assert not result["valid"]
    failures = {check["name"] for check in result["checks"] if not check["valid"]}
    assert failures == {"operation", "key_length"}


def test_validate_major_8a_message():
    result = validate_message(_message(major=0x8A, key_length=4))
    assert result["valid"]


def test_rejects_short_message():
    result = validate_message(_message()[:100])
    assert not result["valid"]
    assert any(check["name"] == "message_size" and not check["valid"] for check in result["checks"])


def test_unknown_family():
    with pytest.raises(ValueError, match="Unknown gencfg family"):
        validate_message(b"", family="unknown")


def test_vrf_group_serializer_round_trip():
    from ablation.analyzers.gencfg import serialize_vrf_group

    message = serialize_vrf_group(7, [10, 20], operation=2, lsys_id=3)
    result = validate_message(message)

    assert result["valid"]
    assert result["blob"]["declared_length"] == 0x98 + 16
    assert [entry["vrf_id"] for entry in result["blob"]["entries"]] == [10, 20]


def test_vrf_group_rejects_count_mismatch_and_missing_change_blob():
    from ablation.analyzers.gencfg import serialize_vrf_group

    message = bytearray(serialize_vrf_group(7, [10]))
    message[0x11C + 0x8C:0x11C + 0x90] = (2).to_bytes(4, "big")
    result = validate_message(message)
    assert not result["valid"]
    assert any(check["name"] == "vrf_count" and not check["valid"] for check in result["checks"])

    result = validate_message(_message(operation=2))
    assert not result["valid"]
    assert any(check["name"] == "blob_present" and not check["valid"] for check in result["checks"])


def test_vrf_group_rejects_zero_length_and_short_entries():
    from ablation.analyzers.gencfg import serialize_vrf_group

    message = bytearray(serialize_vrf_group(7, [10]))
    message[-8:-6] = (3).to_bytes(2, "big")
    message[-6:-4] = (0).to_bytes(2, "big")
    result = validate_message(message)
    failures = {check["name"] for check in result["checks"] if not check["valid"]}
    assert {"entry_0_type", "entry_0_length", "entry_0_progress"} <= failures

    message = bytearray(serialize_vrf_group(7, [10]))[:-2]
    result = validate_message(message)
    assert not result["valid"]
    assert any(check["name"] == "blob_available" and not check["valid"] for check in result["checks"])


def test_vrf_group_rejects_length_arithmetic_overflow():
    from ablation.analyzers.gencfg import serialize_vrf_group

    message = bytearray(serialize_vrf_group(7, [10]))
    message[0x11C + 0x8C:0x11C + 0x90] = (0x20000000).to_bytes(4, "big")
    result = validate_message(message)
    assert not result["valid"]
    assert any(check["name"] == "blob_length_arithmetic" and not check["valid"] for check in result["checks"])
