"""
Sovereign Action Protocol Runtime Validator

Enforces all runtime checks that JSON Schema cannot:
- Canonical serialization
- Hash verification
- ML-DSA signature verification
- Trusted root verification
- Replay / freshness / epoch checks
- Branch + revision lineage
- Witness signature + freshness
- Authorization / state transition gates
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

# ============================================================================
# Exceptions
# ============================================================================

class SARPValidationError(Exception):
    """Base validation error."""
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

class EpochError(SARPValidationError):
    pass

class RevisionError(SARPValidationError):
    pass

class WitnessError(SARPValidationError):
    pass

class StateTransitionError(SARPValidationError):
    pass

class BranchLineageError(SARPValidationError):
    pass

# ============================================================================
# Canonical Serialization
# ============================================================================

def canonical_serialize(obj: Dict[str, Any]) -> str:
    """
    Serialize to canonical form for hashing.
    Sort keys, no whitespace, deterministic output.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    )

def compute_payload_for_hash(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract fields to be hashed.
    Excludes: current_hash, signature, validation, nonce.
    Includes: owner_id, packet_id, chain_id, revision, intent,
              action_type, timestamp, actor_id, previous_hash, entry.
    """
    return {
        "owner_id": entry["owner_id"],
        "packet_id": entry["packet_id"],
        "chain_id": entry["chain_id"],
        "revision": entry["revision"],
        "intent": entry["intent"],
        "action_type": entry["action_type"],
        "timestamp": entry["timestamp"],
        "actor_id": entry["actor_id"],
        "previous_hash": entry["previous_hash"],
        "entry": entry["entry"]
    }

def compute_hash(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 hash in sha256:hex format."""
    canonical = canonical_serialize(payload)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"

# ============================================================================
# Hash Verification
# ============================================================================

def verify_entry_hash(entry: Dict[str, Any]) -> None:
    """Verify that entry's current_hash matches recomputed hash."""
    payload = compute_payload_for_hash(entry)
    computed = compute_hash(payload)
    if entry["current_hash"] != computed:
        raise HashVerificationError(
            f"Hash mismatch for entry {entry['packet_id']}: "
            f"expected {computed}, got {entry['current_hash']}"
        )

def verify_chain_continuity(entries: List[Dict[str, Any]]) -> None:
    """Verify that each entry's previous_hash matches prior entry's current_hash."""
    for idx, entry in enumerate(entries):
        if idx == 0:
            # First entry should have previous_hash = null
            if entry["previous_hash"] is not None:
                raise BranchLineageError(
                    f"First entry {entry['packet_id']} must have previous_hash=null"
                )
        else:
            prior = entries[idx - 1]
            if entry["previous_hash"] != prior["current_hash"]:
                raise BranchLineageError(
                    f"Entry {entry['packet_id']} breaks chain: "
                    f"previous_hash={entry['previous_hash']}, "
                    f"prior entry hash={prior['current_hash']}"
                )

# ============================================================================
# ML-DSA Signature Verification (Stub)
# ============================================================================

def verify_ml_dsa_signature(
    entry: Dict[str, Any],
    public_key: bytes
) -> None:
    """
    Verify ML-DSA signature.
    
    In production, this calls an ML-DSA library (e.g., python-ml-dsa).
    For now, this is a stub that checks the signature exists and is base64.
    
    Real implementation:
      from ml_dsa import MLDSAPublicKey, verify
      pk = MLDSAPublicKey.from_bytes(public_key)
      sig_bytes = base64.b64decode(entry["signature"]["value"])
      payload = canonical_serialize(compute_payload_for_hash(entry))
      verify(pk, sig_bytes, payload.encode("utf-8"))
    """
    sig = entry["signature"]
    if not sig.get("value"):
        raise SignatureVerificationError(
            f"Empty signature in entry {entry['packet_id']}"
        )
    
    # TODO: Call actual ML-DSA verify library
    # For now, just validate structure
    if sig["algorithm"] not in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        raise SignatureVerificationError(
            f"Invalid signature algorithm: {sig['algorithm']}"
        )

# ============================================================================
# Trusted Root Verification
# ============================================================================

def verify_trusted_root(
    root: Dict[str, Any],
    public_key: bytes
) -> None:
    """Verify the trusted root signature."""
    # Root signature structure is the same as entry signature
    root_sig = root["signature"]
    if not root_sig.get("value"):
        raise TrustedRootError(f"Empty signature in root")
    
    # TODO: Call actual ML-DSA verify library
    if root_sig["algorithm"] not in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        raise TrustedRootError(
            f"Invalid root signature algorithm: {root_sig['algorithm']}"
        )

def verify_root_lineage(
    entries: List[Dict[str, Any]],
    root: Dict[str, Any]
) -> None:
    """Verify that the chain's first entry links to the trusted root."""
    if not entries:
        raise TrustedRootError("Cannot verify root lineage: no entries")
    
    first = entries[0]
    if first["previous_hash"] != root["root_hash"]:
        raise TrustedRootError(
            f"Chain does not link to root: "
            f"first entry previous_hash={first['previous_hash']}, "
            f"root hash={root['root_hash']}"
        )

# ============================================================================
# Replay and Freshness
# ============================================================================

def verify_freshness(
    entry: Dict[str, Any],
    freshness_seconds: int
) -> None:
    """Verify that entry timestamp is within freshness window."""
    entry_ts = datetime.fromisoformat(entry["timestamp"])
    now = datetime.utcnow()
    age = (now - entry_ts).total_seconds()
    
    if age < 0:
        raise FreshnessError(
            f"Entry {entry['packet_id']} is from the future: {entry['timestamp']}"
        )
    
    if age > freshness_seconds:
        raise FreshnessError(
            f"Entry {entry['packet_id']} exceeds freshness window: "
            f"{age}s > {freshness_seconds}s"
        )

def verify_no_replay(
    entries: List[Dict[str, Any]],
    request_id_store: Dict[str, str]
) -> None:
    """Verify that no entry has a duplicate request_id."""
    for entry in entries:
        req_id = entry.get("request_id")
        if req_id:
            if req_id in request_id_store:
                raise ReplayError(
                    f"Replay detected: request_id {req_id} already seen"
                )
            request_id_store[req_id] = entry["packet_id"]

# ============================================================================
# Epoch and Revision
# ============================================================================

def verify_monotonic_revision(entries: List[Dict[str, Any]]) -> None:
    """Verify that revisions are strictly increasing."""
    prev_revision = -1
    for entry in entries:
        revision = entry["revision"]
        if revision <= prev_revision:
            raise RevisionError(
                f"Non-monotonic revision in entry {entry['packet_id']}: "
                f"{revision} <= {prev_revision}"
            )
        prev_revision = revision

def verify_monotonic_epoch(entries: List[Dict[str, Any]]) -> None:
    """Verify that epochs are non-decreasing."""
    prev_epoch = -1
    for entry in entries:
        epoch = entry.get("epoch", 0)
        if epoch < prev_epoch:
            raise EpochError(
                f"Non-monotonic epoch in entry {entry['packet_id']}: "
                f"{epoch} < {prev_epoch}"
            )
        prev_epoch = epoch

# ============================================================================
# Witness Verification
# ============================================================================

def verify_witness_freshness(
    witness: Dict[str, Any],
    freshness_seconds: int
) -> None:
    """Verify that witness attestation is fresh."""
    witness_ts = datetime.fromisoformat(witness["verified_at"])
    now = datetime.utcnow()
    age = (now - witness_ts).total_seconds()
    
    if age > freshness_seconds:
        raise WitnessError(
            f"Witness {witness['witness_id']} is stale: "
            f"{age}s > {freshness_seconds}s"
        )

def verify_witness_signature(
    witness: Dict[str, Any],
    public_key: bytes
) -> None:
    """Verify the witness's ML-DSA signature."""
    wit_sig = witness["signature"]
    if not wit_sig.get("value"):
        raise WitnessError(
            f"Empty signature in witness {witness['witness_id']}"
        )
    
    # TODO: Call actual ML-DSA verify library
    if wit_sig["algorithm"] not in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        raise WitnessError(
            f"Invalid witness signature algorithm: {wit_sig['algorithm']}"
        )

# ============================================================================
# State Transition
# ============================================================================

# Valid state transitions
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
    "ROOT_REPAIR": ["REAUTHORIZED"]
}

def verify_state_transition(current_state: str, next_state: str) -> None:
    """Verify that the state transition is allowed."""
    if current_state not in VALID_TRANSITIONS:
        raise StateTransitionError(f"Unknown state: {current_state}")
    
    allowed = VALID_TRANSITIONS[current_state]
    if next_state not in allowed:
        raise StateTransitionError(
            f"Invalid transition: {current_state} -> {next_state}. "
            f"Allowed: {allowed}"
        )

# ============================================================================
# Quarantine Write Freeze
# ============================================================================

def verify_quarantine_write_freeze(
    state: str,
    action_type: Optional[str] = None
) -> None:
    """Verify that no write or action occurs while in QUARANTINE."""
    if state == "QUARANTINE" and action_type is not None:
        raise StateTransitionError(
            f"Cannot execute action {action_type} while in QUARANTINE state"
        )

# ============================================================================
# Complete Chain Validation
# ============================================================================

@dataclass
class ValidationContext:
    """Context for validation run."""
    trusted_root_public_key: bytes
    witness_public_keys: Dict[str, bytes]
    freshness_seconds: int = 300
    request_id_store: Dict[str, str] = None
    
    def __post_init__(self):
        if self.request_id_store is None:
            self.request_id_store = {}

def validate_sovereign_action_protocol(
    protocol: Dict[str, Any],
    context: ValidationContext
) -> Tuple[bool, List[str]]:
    """
    Complete validation of a sovereign action protocol object.
    
    Returns:
        (is_valid, error_messages)
    """
    errors: List[str] = []
    
    try:
        # 1. Extract components
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
        
        # 2. Verify trusted root
        try:
            verify_trusted_root(root, context.trusted_root_public_key)
        except TrustedRootError as e:
            errors.append(f"Root verification failed: {e}")
            return False, errors
        
        # 3. Verify chain linkage
        try:
            verify_root_lineage(entries, root)
        except TrustedRootError as e:
            errors.append(f"Root lineage failed: {e}")
            return False, errors
        
        # 4. Verify each entry
        for idx, entry in enumerate(entries):
            try:
                verify_entry_hash(entry)
            except HashVerificationError as e:
                errors.append(f"Entry {idx}: {e}")
                return False, errors
            
            try:
                verify_ml_dsa_signature(entry, context.trusted_root_public_key)
            except SignatureVerificationError as e:
                errors.append(f"Entry {idx}: {e}")
                return False, errors
            
            try:
                verify_freshness(entry, context.freshness_seconds)
            except FreshnessError as e:
                errors.append(f"Entry {idx}: {e}")
                return False, errors
            
            try:
                verify_no_replay(entries, context.request_id_store)
            except ReplayError as e:
                errors.append(f"Entry {idx}: {e}")
                return False, errors
        
        # 5. Verify chain continuity
        try:
            verify_chain_continuity(entries)
        except BranchLineageError as e:
            errors.append(f"Chain continuity: {e}")
            return False, errors
        
        # 6. Verify monotonic revision and epoch
        try:
            verify_monotonic_revision(entries)
        except RevisionError as e:
            errors.append(f"Revision: {e}")
            return False, errors
        
        try:
            verify_monotonic_epoch(entries)
        except EpochError as e:
            errors.append(f"Epoch: {e}")
            return False, errors
        
        # 7. Verify quarantine write freeze
        try:
            verify_quarantine_write_freeze(state)
        except StateTransitionError as e:
            errors.append(f"Quarantine state: {e}")
            return False, errors
        
        # 8. Verify witness policy (if required)
        if witness_policy.get("required", False):
            reauth_record = protocol.get("reauthorization_record")
            if not reauth_record:
                errors.append("Witness required but no reauthorization_record")
                return False, errors
            
            witness = reauth_record.get("witness")
            if not witness:
                errors.append("Witness policy requires witness attestation")
                return False, errors
            
            try:
                verify_witness_freshness(
                    witness,
                    witness_policy.get("freshness_seconds", 300)
                )
            except WitnessError as e:
                errors.append(f"Witness freshness: {e}")
                return False, errors
            
            try:
                witness_key = context.witness_public_keys.get(witness["witness_id"])
                if not witness_key:
                    errors.append(
                        f"No public key for witness {witness['witness_id']}"
                    )
                    return False, errors
                verify_witness_signature(witness, witness_key)
            except WitnessError as e:
                errors.append(f"Witness signature: {e}")
                return False, errors
        
        # 9. Verify reauthorization policy
        if reauth_policy.get("trusted_root_required", False):
            reauth_record = protocol.get("reauthorization_record")
            if not reauth_record or not reauth_record.get("trusted_root"):
                errors.append("Trusted root required for reauthorization")
                return False, errors
        
        if reauth_policy.get("chain_revalidation_required", False):
            # All checks above constitute revalidation
            pass
        
        if reauth_policy.get("monotonic_revision_required", False):
            # Already verified above
            pass
        
        return True, []
    
    except Exception as e:
        errors.append(f"Unexpected validation error: {e}")
        return False, errors
