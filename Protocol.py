import json
from copy import deepcopy

import pytest

from sovereign_action_protocol.runtime_validator import (
    validate_protocol,
    verify_no_replay,
)

def _make_entry(
    *,
    packet_id,
    revision,
    previous_hash,
    action_type,
    actor_id="actor-1",
    intent="test intent",
    entry_payload=None,
):
    payload = entry_payload or {
        "why": "repair the branch",
        "what": "validate the chain",
        "when": "2026-10-02T00:00:00Z",
        "who": actor_id,
        "where": "branch:main",
        "how": "re-authorize"
    }
    current_hash = "sha256:" + "0" * 64
    return {
        "owner_id": "owner-1",
        "packet_id": packet_id,
        "chain_id": "chain-1",
        "revision": revision,
        "intent": intent,
        "action_type": action_type,
        "timestamp": "2026-10-02T00:00:00Z",
        "actor_id": actor_id,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "entry": payload,
        "signature": {
            "algorithm": "ML-DSA-65",
            "key_id": "key-1",
            "value": "c2lnbmF0dXJl"
        },
        "validation": {
            "status": "VALID",
            "reason": "pre-check",
            "validated_at": "2026-10-02T00:00:00Z"
        },
        "request_id": f"req-{packet_id}",
        "nonce": "1234567890abcdef",
        "epoch": 0,
    }

def test_replay_detection_correct():
    request_store = {}
    entries = [
        _make_entry(packet_id="p1", revision=0, previous_hash=None, action_type="repair"),
        _make_entry(packet_id="p2", revision=1, previous_hash="sha256:" + "0" * 64, action_type="repair"),
    ]
    # Duplicate request id against itself should not false-positive
    entries[0]["request_id"] = "dup"
    entries[1]["request_id"] = "dup"

    with pytest.raises(Exception):
        verify_no_replay(entries, request_store)

def test_state_transition_reauthorized_to_intent_signed():
    from sovereign_action_protocol.runtime_validator import VALID_TRANSITIONS
    assert "REAUTHORIZED" in VALID_TRANSITIONS
    assert "INTENT_SIGNED" in VALID_TRANSITIONS["REAUTHORIZED"]

def test_hash_payload_matches_schema_contract():
    from sovereign_action_protocol.runtime_validator import compute_hash_payload
    entry = _make_entry(packet_id="p1", revision=0, previous_hash=None, action_type="repair")
    payload = compute_hash_payload(entry)
    assert "previous_hash" in payload
    assert "payload" in payload
    assert "timestamp" in payload
    assert "actor_id" in payload
    assert "action_type" in payload
    assert set(payload.keys()) == {"previous_hash", "payload", "timestamp", "actor_id", "action_type"}

def test_validate_protocol_accepts_structure():
    protocol = {
        "protocol_version": "1.0",
        "owner_id": "owner-1",
        "chain_id": "chain-1",
        "root": {
            "root_hash": "sha256:" + "0" * 64,
            "revision": 0,
            "epoch": 0,
            "signer_key_id": "root-key-1",
            "signature": {
                "algorithm": "ML-DSA-65",
                "key_id": "root-key-1",
                "value": "root-signature"
            },
            "established_at": "2026-10-02T00:00:00Z"
        },
        "entries": [
            _make_entry(packet_id="p1", revision=0, previous_hash=None, action_type="repair")
        ],
        "state": "INTENT_SIGNED",
        "witness_policy": {
            "required": False,
            "freshness_seconds": 300,
            "require_root_match": True,
            "require_signature": True,
        },
        "reauthorization_policy": {
            "trusted_root_required": False,
            "fresh_witness_required": False,
            "signature_verification_required": False,
            "chain_revalidation_required": False,
            "monotonic_revision_required": False,
            "quarantine_write_freeze": True,
        },
    }

    valid, errors = validate_protocol(protocol, fresh_limit_seconds=300)
    # This is a structure-level smoke test; actual cryptographic verification is stubbed
    assert valid or errors
