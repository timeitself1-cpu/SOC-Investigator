"""Normalization preserves telemetry identity and source-specific semantics."""

import pytest

from investigator.backends.normalize import normalize_wazuh_doc


def _doc(event_id="4688", **eventdata):
    return {"id": "event-1", "timestamp": "2026-01-01T00:00:00Z", "agent": {"name": "H1"},
            "data": {"win": {"system": {"providerName": "Microsoft-Windows-Security-Auditing",
                                       "channel": "Security", "eventID": event_id},
                             "eventdata": eventdata}}}


def test_4688_uses_new_process_id_and_subject_identity():
    event = normalize_wazuh_doc(_doc(newProcessId="0x4321", processId="0x1234",
                                     newProcessName="C:/Windows/cmd.exe", subjectUserName="alice",
                                     subjectDomainName="LAB"))
    assert event.process_id == 0x4321
    assert event.user == "LAB\\alice"
    assert event.image == "C:/Windows/cmd.exe"


def test_missing_event_identity_is_rejected_instead_of_deduplicated_as_unknown():
    doc = _doc()
    del doc["id"]
    with pytest.raises(ValueError, match="source identity"):
        normalize_wazuh_doc(doc)


def test_invalid_timestamp_is_rejected_not_replaced_with_current_time():
    doc = _doc()
    doc["timestamp"] = "invalid"
    with pytest.raises(ValueError):
        normalize_wazuh_doc(doc)


def test_guid_capitalization_variants_are_preserved():
    event = normalize_wazuh_doc(_doc(processGUID="{proc}", parentProcessGUID="{parent}"))
    assert event.process_guid == "{proc}"
    assert event.parent_process_guid == "{parent}"
