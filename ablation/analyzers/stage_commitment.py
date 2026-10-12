"""StageCommitment — No-Lock/Approving audit chain for multi-session RE pipelines.

Three gaps this closes:

1. FORGE is a point-in-time gate; it does not persist a hash of what passed.
   When a finding is revised after confirmation there is no record of the original
   committed content or which session produced it.

2. Multi-session review has no tamper-evidence.  If two agents work on the same
   target across sessions there is no way to detect whether findings were altered
   between sessions without reading both SESSION.md files and diffing by hand.

3. The connection between a confirmed finding and its originating workflow stage
   is not machine-checkable.  FindingRegistry stores findings; it does not record
   how they were produced or who approved them.

Pattern (derived from IBM XFDL No-Lock/Approving signatures):

- Producer calls ``commit()`` with ``lock_mode="no-lock"``.  The content hash is
  recorded but the instance is not frozen — the reviewer may revise it.
- Reviewer calls ``approve()``, optionally passing a ``revised_instance``.  The
  approving hash covers the original ``content_hash`` plus the hash of the revised
  (or original) content, binding both the original commitment and the final result.
- ``verify()`` checks whether the current instance matches the committed or
  approved-revision hash.  Any other value is a tampered state.

Usage::

    sc = StageCommitment(doc_id="cisco/fmc_server")

    # producer commits without locking content
    rec = sc.commit("finding_confirmation", instance, producer="session-42")

    # reviewer approves with optional revision
    rec2 = sc.approve("finding_confirmation", approver="session-43",
                       revised_instance=None)  # None = accept unchanged

    # verify at any later point
    ok, reason = sc.verify("finding_confirmation", instance)
    assert ok

    # human-readable chain report
    print(sc.audit_trail())

    # persist across sessions
    Path("commitments.json").write_text(sc.to_json())
    sc2 = StageCommitment.from_json(Path("commitments.json").read_text())
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _instance_hash(instance: dict) -> str:
    return _sha256(json.dumps(instance, sort_keys=True))


@dataclass
class CommitmentRecord:
    """Single stage commitment with optional approving countersignature."""

    stage_name: str
    producer: str
    content_hash: str
    timestamp: str
    lock_mode: str
    approver: str | None = None
    revised_content_hash: str | None = None
    approving_hash: str | None = None


class StageCommitment:
    """Tamper-evident audit chain for WorkflowDocument stage outputs.

    Each stage can be committed once by a producer and approved once by a
    reviewer.  ``verify()`` confirms that the current instance matches the
    committed or approved-revision hash, detecting any out-of-band mutation.
    """

    def __init__(self, doc_id: str = "") -> None:
        self.doc_id = doc_id
        self._records: dict[str, CommitmentRecord] = {}

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def commit(
        self,
        stage_name: str,
        instance: dict,
        producer: str,
        lock_mode: str = "no-lock",
    ) -> CommitmentRecord:
        """Record a content hash for *stage_name*.

        ``lock_mode="no-lock"`` allows a reviewer to revise the content and
        countersign with ``approve()``.  ``lock_mode="locked"`` signals that
        the producer intends no revision, but does not enforce it structurally.
        """
        if lock_mode not in ("no-lock", "locked"):
            raise ValueError(
                f"lock_mode must be 'no-lock' or 'locked', got {lock_mode!r}"
            )
        if not producer:
            raise ValueError("producer must be a non-empty string")
        rec = CommitmentRecord(
            stage_name=stage_name,
            producer=producer,
            content_hash=_instance_hash(instance),
            timestamp=datetime.now(timezone.utc).isoformat(),
            lock_mode=lock_mode,
        )
        self._records[stage_name] = rec
        return rec

    def approve(
        self,
        stage_name: str,
        approver: str,
        revised_instance: dict | None = None,
    ) -> CommitmentRecord:
        """Countersign a committed stage, optionally with a revised instance.

        The approving hash covers the original ``content_hash`` plus the hash
        of the revised (or, if *revised_instance* is None, empty) content.
        This binds the approver to both what the producer originally committed
        and to the final content they accept.

        Raises ``KeyError`` if *stage_name* has no prior commitment.
        Raises ``ValueError`` if *approver* is empty.
        """
        if stage_name not in self._records:
            raise KeyError(f"no commitment found for stage {stage_name!r}")
        if not approver:
            raise ValueError("approver must be a non-empty string")
        rec = self._records[stage_name]
        if revised_instance is not None:
            rev_hash = _instance_hash(revised_instance)
            rec.revised_content_hash = rev_hash
        else:
            rev_hash = ""
        rec.approver = approver
        rec.approving_hash = _sha256(rec.content_hash + rev_hash)
        rec.timestamp = datetime.now(timezone.utc).isoformat()
        return rec

    def verify(
        self,
        stage_name: str,
        current_instance: dict,
    ) -> tuple[bool, str]:
        """Check whether *current_instance* matches the committed or approved state.

        Returns ``(True, "ok")`` when the chain is intact.  Returns
        ``(False, reason)`` when the content does not match any committed hash,
        indicating out-of-band mutation or an unverifiable state.
        """
        if stage_name not in self._records:
            return False, f"no commitment for stage {stage_name!r}"
        rec = self._records[stage_name]
        current_hash = _instance_hash(current_instance)

        if current_hash == rec.content_hash:
            return True, "ok"

        if rec.revised_content_hash and current_hash == rec.revised_content_hash:
            # Verify the approving hash covers original + revised
            expected = _sha256(rec.content_hash + rec.revised_content_hash)
            if rec.approving_hash == expected:
                return True, "ok (approved revision)"
            return False, "approving hash mismatch — chain corrupted"

        parts = [
            f"content mutated: original {rec.content_hash[:12]}",
        ]
        if rec.revised_content_hash:
            parts.append(f"approved revision {rec.revised_content_hash[:12]}")
        parts.append(f"current {current_hash[:12]}")
        return False, " / ".join(parts)

    def audit_trail(self) -> str:
        """Return a human-readable table of all commitments and their chain status."""
        if not self._records:
            return f"StageCommitment doc_id={self.doc_id!r}: no commitments"
        col = 24
        lines = [f"StageCommitment doc_id={self.doc_id!r}"]
        lines.append(
            f"  {'stage':<{col}} {'producer':<14} {'lock':<10}"
            f" {'approver':<14} chain"
        )
        lines.append("  " + "-" * 72)
        for name, rec in self._records.items():
            chain = "approved" if rec.approving_hash else "pending"
            approver = rec.approver or "-"
            lines.append(
                f"  {name:<{col}} {rec.producer:<14} {rec.lock_mode:<10}"
                f" {approver:<14} {chain}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialise all commitment records to a JSON string."""
        return json.dumps(
            {
                "doc_id": self.doc_id,
                "records": {k: asdict(v) for k, v in self._records.items()},
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, s: str) -> "StageCommitment":
        """Deserialise a StageCommitment produced by ``to_json()``."""
        d = json.loads(s)
        obj = cls(doc_id=d.get("doc_id", ""))
        for k, v in d.get("records", {}).items():
            obj._records[k] = CommitmentRecord(**v)
        return obj
