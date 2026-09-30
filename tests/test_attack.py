"""Regression cases for overly broad, duplicated and uncorrelated support."""

from datetime import datetime, timedelta, timezone

import pytest

from investigator.attack import claim_supported, technique_supported
from investigator.evidence import EvidenceStore
from investigator.models import NormalizedEvent


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evidence(*events):
    store = EvidenceStore("fixture")
    for i, fields in enumerate(events):
        values = dict(event_ref=str(i), timestamp=NOW, host="H1", source="sysmon")
        values.update(fields)
        store.add(NormalizedEvent(**values), "test")
    return store.all()


@pytest.mark.parametrize("claim", ["command_and_control", "payload_download", "data_exfiltration", "lateral_movement", "privilege_escalation"])
def test_generic_network_does_not_prove_attack_outcomes(claim):
    evs = evidence(dict(category="network", dest_ip="8.8.8.8", dest_port=443))
    assert not claim_supported(claim, evs)[0]


@pytest.mark.parametrize("technique", ["T1105", "T1071.001"])
def test_web_port_does_not_prove_transfer_or_c2(technique):
    assert not technique_supported(technique, evidence(dict(category="network", dest_ip="8.8.8.8", dest_port=443)))[0]


def test_dns_does_not_prove_a_connection():
    assert not claim_supported("network_connection", evidence(dict(category="dns", query_name="example.org")))[0]


@pytest.mark.parametrize("claim", ["discovery", "benign_administration", "privilege_escalation"])
def test_generic_process_is_not_discovery_administration_or_escalation(claim):
    assert not claim_supported(claim, evidence(dict(category="process", image="notepad.exe")))[0]


def test_lsass_query_access_and_unrelated_dump_do_not_prove_theft():
    access = dict(category="process_access", target_image="lsass.exe", granted_access="0x1000", process_guid="P1")
    dump = dict(category="file", target_filename=r"C:\Temp\lsass.dmp", process_guid="P1", timestamp=NOW + timedelta(seconds=1))
    assert not claim_supported("credential_theft", evidence(access, dump))[0]
    access["granted_access"] = "0x1fffff"
    assert claim_supported("credential_theft", evidence(access, dump))[0]
    assert technique_supported("T1003.001", evidence(access, dump))[0]
    for changed in ({"process_guid": "P2"}, {"host": "H2"}, {"process_guid": None},
                    {"timestamp": NOW - timedelta(seconds=1)}, {"timestamp": NOW + timedelta(hours=1)}):
        assert not claim_supported("credential_theft", evidence(access, dump | changed))[0]
    assert not claim_supported("credential_theft", evidence(access))[0]
    assert not claim_supported("credential_theft", evidence(dump))[0]


def auth(outcome="failure", **changes):
    return dict(category="authentication", user=r"CORP\alice", src_ip="8.8.8.8", auth_outcome=outcome) | changes


def test_duplicate_evidence_cannot_manufacture_brute_force():
    ev = evidence(auth())[0]
    assert not claim_supported("brute_force", [ev, ev, ev])[0]
    assert not technique_supported("T1110", [ev, ev, ev])[0]


@pytest.mark.parametrize("changed", [{"user": "bob"}, {"host": "H2"}, {"src_ip": "1.1.1.1"},
                                     {"timestamp": NOW + timedelta(hours=1)}, {"user": None}, {"src_ip": None}])
def test_brute_force_requires_correlated_failures(changed):
    assert not claim_supported("brute_force", evidence(auth(), auth(), auth(**changed)))[0]


def test_account_compromise_requires_failures_before_same_identity_success():
    failures = [auth(timestamp=NOW + timedelta(seconds=i)) for i in range(3)]
    success = auth("success", timestamp=NOW + timedelta(seconds=3))
    assert claim_supported("brute_force", evidence(*failures))[0]
    assert claim_supported("account_compromise", evidence(*failures, success))[0]
    assert not claim_supported("account_compromise", evidence(success))[0]
    for changed in ({"user": "bob"}, {"host": "H2"}, {"src_ip": "1.1.1.1"},
                    {"timestamp": NOW}, {"timestamp": NOW + timedelta(hours=1)}):
        assert not claim_supported("account_compromise", evidence(*failures, success | changed))[0]


def test_office_ancestry_not_proof_of_malicious_user_execution():
    evs = evidence(dict(category="process", image="powershell.exe", parent_image="winword.exe"))
    assert claim_supported("office_child_process", evs)[0]
    assert not technique_supported("T1204.002", evs)[0]


def test_failed_rdp_does_not_prove_remote_execution():
    assert not technique_supported("T1021.001", evidence(auth(logon_type=10)))[0]
    assert technique_supported("T1021.001", evidence(auth("success", logon_type=10)))[0]


def test_net_use_is_not_account_discovery():
    assert not technique_supported("T1087", evidence(dict(category="process", image="net.exe", command_line="net use Z: \\\\server\\share")))[0]
    assert technique_supported("T1087", evidence(dict(category="process", image="net.exe", command_line="net user /domain")))[0]
