import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

class SARPValidationError(Exception):
    pass

class CanonicalSerializationError(SARPValidationError):
    pass

class HashVerificationError(SARPValidationError):
    pass

class SignatureVerificationError(SARPValidationError):
    pass

class TrustedRootError(SARPValidationError):
    pass

class ReplayError(SARPValidationError):
    pass

class FreshnessError(SARPValidationError):
    pass

class RevisionError(SARPValidationError):
    pass

class EpochError(SARPValidationError):
    pass

class WitnessError(SARPValidationError):
    pass

class StateTransitionError(SARPValidationError):
    pass

class BranchLineageError(SARPValidationError):
    pass


def canonical_serialize(obj: Any) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    )

def compute_hash(payload: Dict[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_serialize(payload).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"

def compute_hash_payload(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    This matches the schema contract:
    previous_hash || payload || timestamp || actor_id || action_type
    where payload is the 5W1H entry object.
    """
    return {
        "previous_hash": entry["previous_hash"],
        "payload": entry["entry"],
        "timestamp": entry["timestamp"],
        "actor_id": entry["actor_id"],
        "action_type": entry["action_type"],
    }

def verify_entry_hash(entry: Dict[str, Any]) -> None:
    computed = compute_hash(compute_hash_payload(entry))
    if entry["current_hash"] != computed:
        raise HashVerificationError(
            f"Hash mismatch for {entry.get('packet_id')}: "
            f"expected {computed}, got {entry['current_hash']}"
        )

def verify_chain_continuity(entries: List[Dict[str, Any]]) -> None:
    for idx, entry in enumerate(entries):
        if idx == 0:
            if entry["previous_hash"] is not None:
                raise BranchLineageError(
                    "First entry previous_hash must be null"
                )
        else:
            prev = entries[idx - 1]
            if entry["previous_hash"] != prev["current_hash"]:
                raise BranchLineageError(
                    f"Entry {entry['packet_id']} does not continue prior hash"
                )

def verify_no_replay(
    entries: List[Dict[str, Any]],
    request_id_store: Dict[str, str],
) -> None:
    """
    The key fix: check against the store first, then add the current entries
    after the full pass succeeds.
    """
    for entry in entries:
        req_id = entry.get("request_id")
        if req_id and req_id in request_id_store:
            raise ReplayError(f"Replay detected: {req_id}")

    for entry in entries:
        req_id = entry.get("request_id")
        if req_id:
            request_id_store[req_id] = entry["packet_id"]

def verify_freshness(entry: Dict[str, Any], freshness_seconds: int) -> None:
    try:
        ts = datetime.fromisoformat(entry["timestamp"])
    except ValueError as exc:
        raise FreshnessError(f"Invalid timestamp: {entry['timestamp']}") from exc

    age = (datetime.utcnow() - ts).total_seconds()
    if age < 0:
        raise FreshnessError(f"Entry {entry['packet_id']} is from the future")
    if age > freshness_seconds:
        raise FreshnessError(
            f"Entry {entry['packet_id']} exceeds freshness limit"
        )

def verify_monotonic_revision(entries: List[Dict[str, Any]]) -> None:
    prev = -1
    for entry in entries:
        rev = entry["revision"]
        if rev <= prev:
            raise RevisionError(
                f"Revision not monotonic: {entry['packet_id']} {rev} <= {prev}"
            )
        prev = rev

def verify_monotonic_epoch(entries: List[Dict[str, Any]]) -> None:
    prev = -1
    for entry in entries:
        epoch = entry.get("epoch", 0)
        if epoch < prev:
            raise EpochError(
                f"Epoch not monotonic: {entry['packet_id']} {epoch} < {prev}"
            )
        prev = epoch

def verify_trusted_root(root: Dict[str, Any]) -> None:
    required = {"root_hash", "revision", "epoch", "signer_key_id", "signature", "established_at"}
    missing = required - root.keys()
    if missing:
        raise TrustedRootError(f"Missing root fields: {sorted(missing)}")

def verify_root_lineage(entries: List[Dict[str, Any]], root: Dict[str, Any]) -> None:
    if not entries:
        raise TrustedRootError("No entries to validate")
    first = entries[0]
    if first["previous_hash"] != root["root_hash"]:
        raise TrustedRootError("Chain does not link to trusted root")

def verify_ml_dsa_signature(entry: Dict[str, Any], public_key: bytes) -> None:
    """
    Stub intentionally honest: runtime crypto validation is still required.
    Replace with actual ML-DSA verify call.
    """
    sig = entry["signature"]
    if not sig.get("value"):
        raise SignatureVerificationError("Empty signature")
    if sig["algorithm"] not in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
        raise SignatureVerificationError("Unsupported algorithm")

def verify_witness_freshness(witness: Dict[str, Any], freshness_seconds: int) -> None:
    ts = datetime.fromisoformat(witness["verified_at"])
    age = (datetime.utcnow() - ts).total_seconds()
    if age > freshness_seconds:
        raise WitnessError("Witness attestation stale")

def verify_witness_signature(witness: Dict[str, Any], public_key: bytes) -> None:
    sig = witness["signature"]
    if not sig.get("value"):
        raise WitnessError("Empty witness signature")
    if sig["algorithm"] not in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
        raise WitnessError("Unsupported witness algo")

VALID_TRANSITIONS = {
    "INIT": ["INTENT_SIGNED"],
    "INTENT_SIGNED": ["VALIDATION_PENDING"],
    "VALIDATION_PENDING": ["VALID", "INVALID"],
    "VALID": ["REPAIR_PATH", "SABOTAGE_PATH"],
    "REPAIR_PATH": ["CHAIN_EXTEND"],
    "CHAIN_EXTEND": ["WITNESS_RECYCLE"],
    "WITNESS_RECYCLE": ["CONSTELLATION_RESYNC"],
    "CONSTELLATION_RESYNC": ["REAUTHORIZED"],
    "SABOTAGE_PATH": ["CHAIN_SNAP"],
    "CHAIN_SNAP": ["QUARANTINE"],
    "INVALID": ["QUARANTINE"],
    "QUARANTINE": ["ROOT_REPAIR"],
    "ROOT_REPAIR": ["REAUTHORIZED"],
    "REAUTHORIZED": ["INTENT_SIGNED"],  # closes the loop
}

def verify_state_transition(current_state: str, next_state: str) -> None:
    if current_state not in VALID_TRANSITIONS:
        raise StateTransitionError(f"Unknown current state: {current_state}")
    legal = VALID_TRANSITIONS[current_state]
    if next_state not in legal:
        raise StateTransitionError(
            f"Invalid transition: {current_state} -> {next_state}"
        )

def verify_quarantine_write_freeze(state: str, action_type: Optional[str] = None) -> None:
    if state == "QUARANTINE" and action_type is not None:
        raise StateTransitionError(
            "Cannot execute write while in QUARANTINE"
        )

def validate_protocol(protocol: Dict[str, Any], *, fresh_limit_seconds: int = 300) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    try:
        root = protocol.get("root")
        entries = protocol.get("entries", [])
        state = protocol.get("state")
        witness_policy = protocol.get("witness_policy", {})
        reauth_policy = protocol.get("reauthorization_policy", {})

        if not root:
            errors.append("Missing root")
            return False, errors

        if not entries:
            errors.append("Empty entries list")
            return False, errors

        verify_trusted_root(root)
        verify_root_lineage(entries, root)
        verify_chain_continuity(entries)

        seen_request_ids: Dict[str, str] = {}
        verify_no_replay(entries, seen_request_ids)

        verify_monotonic_revision(entries)
        verify_monotonic_epoch(entries)

        for idx, entry in enumerate(entries):
            verify_entry_hash(entry)
            verify_ml_dsa_signature(entry, b"placeholder-public-key")
            verify_freshness(entry, fresh_limit_seconds)

        if state:
            # state transition validation
            current = protocol.get("previous_state")
            if current is not None:
                verify_state_transition(current, state)

        if witness_policy.get("required") is True:
            witness = protocol.get("reauthorization_record", {}).get("witness")
            if not witness:
                errors.append("Witness required but not provided")
                return False, errors
            verify_witness_freshness(witness, witness_policy.get("freshness_seconds", 300))
            verify_witness_signature(witness, b"placeholder-witness-key")

        if reauth_policy.get("trusted_root_required") is True:
            reauth = protocol.get("reauthorization_record")
            if not reauth or not reauth.get("trusted_root"):
                errors.append("Trusted root required for reauthorization")
                return False, errors

        return True, []

    except Exception as exc:
        errors.append(str(exc))
        return False, errors
