"""Issuing and verifying an evaluation receipt.

The product objective is that an evaluation result should never silently follow
a changed agent configuration. The *enforceable* invariant is narrower, and the
difference is the project's own boundary rather than a caveat bolted on:

    An evaluation result may be released only when the presented deployment
    configuration resolves to the same declared configuration identity that
    earned the result.

"Presented" is doing real work there. EvalSeal resolves the artifacts handed to
it for verification. Establishing what a process actually loaded and ran is
EFFECTIVE/EXECUTED attestation, and is outside v0 -- see ``scope`` below.

A receipt is issued only when two conditions hold together, and both are
recorded in it:

    1. the evaluation ran against a configuration with a computable identity
    2. the eval set passed its integrity check (no structural contamination)

Condition 2 is what makes this more than a hash of a config. An evaluation
result from a contaminated held-out set is not a weaker result, it is a
different claim, and a system that seals it without checking is laundering it.

The receipt embeds the *profile declaration*, not just the profile name, so
someone verifying it a year from now can see which transformations were treated
as meaning-preserving without trusting that the name still means the same thing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .address import addr_of, short
from .canonical import profile_declaration
from .materiality import MaterialityPolicy
from .leakage import LeakageReport
from .manifest import Manifest
from .sign import load_or_create_key, public_key_hex, sign_payload, verify_payload

__all__ = ["Receipt", "issue", "load", "verify_against"]

RECEIPT_VERSION = "evalseal/receipt/v1"


@dataclass
class Receipt:
    payload: dict[str, Any]
    signature: str
    public_key: str

    @property
    def configuration_address(self) -> str:
        return self.payload["configuration"]["address"]

    @property
    def approved(self) -> bool:
        return self.payload["release"]["status"] == "APPROVED"

    def to_json(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature, "public_key": self.public_key}

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=2, ensure_ascii=False), encoding="utf-8")

    def address(self) -> str:
        """The receipt's own address, for referencing from runtime audit events."""
        return addr_of(self.payload, self.payload["profile"]["name"])


def issue(
    manifest: Manifest,
    eval_results: dict[str, Any],
    leakage: LeakageReport | None,
    approver: str,
    key_path: str | Path,
    agent_name: str,
    release_label: str | None = None,
    leakage_policy: str = "block_on_structural",
    materiality: MaterialityPolicy | None = None,
    corpus_scope: str = "full",
    envelope: Any = None,
    evaluated: list[Manifest] | None = None,
) -> Receipt:
    """Build, sign and return a receipt.

    ``leakage_policy`` is declared in the receipt because it is a judgement
    call, not a fact: ``block_on_structural`` fails the release when
    deterministic contamination is found and merely records the probabilistic
    level-2 candidates. Blocking on a lexical similarity threshold would make
    releases hostage to a tunable number, which is the wrong place for one.

    ``envelope`` turns this into an *envelope receipt*: it licenses every run
    that is a member of the declared configuration class AND meets every material
    evaluation condition, rather than one exact address. ``evaluated`` is the list
    of manifests actually evaluated, and the class's enumerated members must all
    appear among them -- checked here, at issuance, so an envelope wider than its
    evidence is never signed in the first place. Omit both and nothing below
    changes: a point receipt is byte-identical to what it was before this feature
    existed.
    """
    profile = manifest.profile

    class_block: dict[str, Any] | None = None
    if envelope is not None:
        from .classes import covered_by, evaluated_members

        envelope.validate()
        cls = envelope.configuration_class
        basis = evaluated if evaluated is not None else [manifest]
        exercised = evaluated_members(basis)
        covered, problems = covered_by(cls, exercised)
        if not covered:
            raise ValueError(
                "refusing to issue an envelope whose configuration class names members no "
                "evaluated configuration exercised:\n  " + "\n  ".join(problems)
            )
        class_block = {
            **envelope.declare(),
            "address": envelope.address(),
            # The evidence, recorded inside the signature, so a verifier can
            # re-run the coverage check a year from now without the evaluations.
            "exercised_members": exercised,
            "licenses":
                "Inheritance of this evidence by any run that is a member of the declared "
                "configuration class AND meets every material condition. NOT behavioural "
                "equivalence between members: two configurations satisfying one subset "
                "constraint may behave entirely differently.",
            "conditions_are_declared":
                "Conditions are declared by the presenter, not attested. This establishes "
                "that the presented conditions match the evaluated ones; it does not "
                "establish that either description was true.",
        }

    integrity: dict[str, Any] = {"checked": leakage is not None}
    if leakage is not None:
        det = {m: s.detected for m, s in leakage.scores.items()}
        integrity.update(
            {
                "policy": leakage_policy,
                "byte_matches": det["byte"],
                "structural_matches": det["structural"],
                "lexical_candidates": det["lexical"],
                "lexical_backend": leakage.backend,
                "tau": leakage.tau,
                "n_eval_items": leakage.n_eval,
                "n_corpus_items": leakage.n_corpus,
                # Zero comparisons is the absence of a result, not a clean one.
                # report.render_leakage refuses to print CLEAN for this case; the
                # signed payload must not assert it either.
                "clean": (det["structural"] == 0
                          and leakage.n_eval > 0 and leakage.n_corpus > 0),
                "comparisons_possible": leakage.n_eval > 0 and leakage.n_corpus > 0,
            }
        )

    eval_clean = integrity.get("clean", True) if leakage is not None else True
    tests_pass = eval_results.get("failed", 0) == 0 or eval_results.get("gate") == "pass"
    status = "APPROVED" if (eval_clean and tests_pass) else "BLOCKED"

    reasons: list[str] = []
    if not eval_clean:
        reasons.append(
            f"eval set contaminated: {integrity['structural_matches']} structural match(es) "
            f"against the candidate corpus"
        )
    if not tests_pass:
        reasons.append(f"evaluation gate not met: {eval_results.get('failed')} failing item(s)")

    payload = {
        "version": RECEIPT_VERSION,
        "agent": agent_name,
        "release": {
            "label": release_label or datetime.now(timezone.utc).strftime("%Y-%m-%d.1"),
            "status": status,
            "reasons": reasons,
            "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "approved_by": approver,
        },
        # The declaration travels with the receipt, not just the name.
        "profile": profile_declaration(profile),
        # Which fields are compared, under which relation, and which are
        # excluded. A verifier a year from now must be able to see the
        # equivalence relation this evidence was issued under rather than infer
        # it, and the policy is a declared, contestable choice -- not a
        # universal canonical form. Absent means: the default relation applies
        # to every field, with no exclusions.
        "materiality": (dict(materiality.declare(), corpus_scope=corpus_scope)
                        if materiality else {
            "corpus_scope": corpus_scope,
            "name": "evalseal/materiality/v0-implicit",
            "default_relation": profile,
            "rules": [],
            "note": "No per-field policy declared: the default relation applies uniformly "
                    "and nothing is excluded from comparison. corpus_scope 'resolved' binds "
                    "only the documents the evaluation actually read; 'full' binds every "
                    "document present.",
        }),
        "configuration": {
            "address": manifest.configuration_address,
            "components": manifest.addresses(),
        },
        # Present only on a class receipt. Its absence is what makes a point
        # receipt a point receipt, so the point path below is untouched by this
        # feature: no key, no class branch, identical behaviour.
        **({"evidence_envelope": class_block} if class_block else {}),
        "evaluation": eval_results,
        "eval_integrity": integrity,
        # Stated limits, inside the signed artifact. A receipt that overclaims
        # is worse than no receipt, so the boundary is part of the signed
        # payload rather than a footnote someone can drop from a slide.
        "scope": {
            # The central boundary: DECLARED != EFFECTIVE != EXECUTED.
            # EvalSeal operates entirely at DECLARED. It binds the configuration
            # artifacts an operator presents, and recomputes their identity at
            # runtime. It does not observe the running process, so it cannot
            # establish that the loaded prompt, the served model or the live
            # tool handlers correspond to these artifacts. A verifier that
            # treated a VERIFIED result as execution provenance would be
            # overclaiming, and that promotion is the failure this field exists
            # to prevent.
            "layer": "DECLARED",
            # The enforceable invariant, stated in the signed artifact so that
            # what this receipt licenses cannot drift from what it proves.
            "invariant":
                "An evaluation result may be released only when the presented deployment "
                "configuration resolves to the same declared configuration identity that "
                "earned the result. Establishing what a process actually loaded and ran is "
                "EFFECTIVE/EXECUTED attestation and is outside EvalSeal v0.",
            "declared_vs_executed":
                "Establishes that the configuration artifacts presented at runtime are "
                "identical to those evaluated. Does NOT establish that they were loaded, "
                "served, or used to produce any particular output.",
            "model_identity":
                "Provider-supplied identifier. Weights, adapters, quantizations and "
                "tokenizers are not canonicalized. Where serving is dynamic -- request-level "
                "routing, mixture-of-agents committees, models partitioned across peers -- "
                "the effective artifact set may not be knowable to the agent at all, so an "
                "agent-side declaration cannot be treated as effective-model provenance.",
            "leakage_claim":
                "Corpus overlap between the eval set and a candidate corpus. NOT proof of "
                "training exposure, which requires membership inference.",
            "level2_evidence":
                "Probabilistic lexical similarity. Recorded, never gating.",
            "signature_meaning":
                "Establishes the integrity of this declaration since it was signed. Does NOT "
                "independently establish that the declaration is true. Establishes the "
                "AUTHORITY of the signer only when the verifier checks the signing key "
                "against a set of keys authorised to approve releases; with no such set, "
                "anyone can mint a receipt that verifies. See trust_anchored on the "
                "verification result.",
            "address_scheme":
                "es1, local to EvalSeal. No byte compatibility with any other "
                "content-addressing scheme is claimed or implied.",
        },
    }

    key = load_or_create_key(key_path)
    return Receipt(
        payload=payload,
        signature=sign_payload(payload, key, profile),
        public_key=public_key_hex(key),
    )


def load(path: str | Path) -> Receipt:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return Receipt(payload=d["payload"], signature=d["signature"], public_key=d["public_key"])


@dataclass
class VerificationResult:
    signature_valid: bool
    configuration_match: bool
    receipt_approved: bool
    approved_address: str
    runtime_address: str
    diff: dict[str, Any] = field(default_factory=dict)
    # Present only when the receipt carried a configuration class. A point
    # verification leaves these at their defaults and behaves exactly as before.
    class_decision: Any = None
    class_address: str = ""
    # Whether the signing key was checked against a set of keys authorised to
    # approve releases. Without that check a signature establishes only that the
    # payload has not been altered since it was signed -- by whoever signed it.
    # Anyone can generate a keypair and mint a receipt, so an unanchored
    # signature is integrity, not authority, and the two must not be reported as
    # if they were the same thing.
    trust_anchored: bool = False

    @property
    def permitted(self) -> bool:
        return self.signature_valid and self.configuration_match and self.receipt_approved

    @property
    def verdict(self) -> str:
        # A class verdict must never read like a point verdict. ADMISSIBLE is a
        # weaker statement than VERIFIED -- this configuration was not evaluated;
        # it is a member of a class that was licensed -- and printing the same
        # word for both would be the same overclaim as reporting an unanchored
        # signature as authority.
        if self.class_decision is not None:
            if self.permitted:
                tail = "" if self.trust_anchored else ", signer not anchored"
                return f"ADMISSIBLE (inside envelope {self.class_address[:12]}{tail})"
            if not self.signature_valid:
                return "BLOCKED (receipt signature invalid)"
            if not self.receipt_approved:
                return "BLOCKED (receipt was never approved)"
            outside = ", ".join(self.class_decision.outside())
            return f"OUTSIDE ENVELOPE ({outside})"
        if self.permitted:
            return "VERIFIED" if self.trust_anchored else "VERIFIED (signer not anchored)"
        if not self.signature_valid:
            return "BLOCKED (receipt signature invalid)"
        if not self.receipt_approved:
            return "BLOCKED (receipt was never approved)"
        return "BLOCKED (configuration drift)"

    def licenses(self) -> dict[str, bool]:
        """Exactly which conclusions this verification supports."""
        out = {
            "integrity of the declaration": self.signature_valid,
            "authority of the approver": self.signature_valid and self.trust_anchored,
            "identity of presented artifacts": self.configuration_match,
            "evaluation cleared this configuration": self.receipt_approved,
            "execution": False,
            "effective model": False,
        }
        if self.class_decision is not None:
            # A class receipt licenses membership, not identity: this exact
            # configuration was never evaluated, and saying "identity of presented
            # artifacts" would claim it was.
            del out["identity of presented artifacts"]
            out["this run is inside the declared envelope"] = self.configuration_match
            out["evaluation cleared this configuration"] = False
            out["evaluation cleared this envelope"] = self.receipt_approved
            out["behavioural equivalence between members"] = False
            # Conditions are presented, not observed. Same boundary as the
            # configuration artifacts themselves.
            out["conditions were as declared"] = False
        return out


def verify_against(
    receipt: Receipt,
    runtime_manifest: Manifest,
    diff: dict[str, Any] | None = None,
    trusted_keys: set[str] | None = None,
    runtime_conditions: dict[str, str] | None = None,
) -> VerificationResult:
    """Recompute at runtime and compare with what was sealed.

    ``runtime_conditions`` are the evaluation conditions the RUN presents -- network
    reachability, human intervention, and whatever else the envelope declared
    material. Only consulted for an envelope receipt. A material condition the run
    does not report fails closed: an unreported control is not a satisfied one.

    ``trusted_keys`` is the set of ed25519 public keys (hex) authorised to
    approve a release. Without it, the signature is checked against the key
    carried *inside the receipt*, which proves the payload has not been altered
    since signing but proves nothing about who signed it: anyone can generate a
    keypair and mint a receipt that verifies. The result records which case
    applied rather than reporting both as "VERIFIED", because conflating
    integrity with authority is the same category of error as conflating a
    declaration with execution.

    A receipt signed by a key outside ``trusted_keys`` fails closed.
    """
    profile = receipt.payload["profile"]["name"]
    sig_ok = verify_payload(receipt.payload, receipt.signature, receipt.public_key, profile)
    anchored = False
    if trusted_keys is not None:
        anchored = receipt.public_key in trusted_keys
        sig_ok = sig_ok and anchored
    match = receipt.configuration_address == runtime_manifest.configuration_address

    # Class branch. Entered only when the receipt carries a class, so a point
    # receipt takes exactly the path it took before this existed.
    decision = None
    class_address = ""
    class_decl = receipt.payload.get("evidence_envelope")
    if class_decl is not None:
        from .classes import ClassDecision, InadmissibleClass, covered_by
        from .envelope import InadmissibleEnvelope, check, envelope_from_declaration

        try:
            env = envelope_from_declaration(class_decl)
            cls = env.configuration_class
            class_address = env.address()
            decision = check(env, runtime_manifest, runtime_conditions)
        except (InadmissibleClass, InadmissibleEnvelope) as e:
            # A malformed class is the absence of a check, which at a deployment
            # gate must read as a refusal rather than an exception thrown past the
            # caller. The verdict says OUTSIDE CLASS and the finding says why.
            class_address = str(class_decl.get("address", ""))
            return VerificationResult(
                signature_valid=sig_ok,
                configuration_match=False,
                receipt_approved=receipt.approved,
                approved_address=receipt.configuration_address,
                runtime_address=runtime_manifest.configuration_address,
                diff=diff or {},
                trust_anchored=anchored,
                class_address=class_address,
                class_decision=ClassDecision(
                    ok=False, class_address=class_address,
                    findings=[{"component": "class", "relation": "well-formed",
                               "ok": False, "detail": str(e)}],
                ),
            )

        # The declaration must re-address to the address recorded beside it, or
        # the object being checked is not the object that was approved. Recorded
        # as a failed finding rather than raised: a deployment gate needs a
        # verdict it can act on, and an exception escaping past the gate is how a
        # check becomes a crash instead of a refusal.
        if class_address != class_decl.get("address"):
            decision.ok = False
            decision.class_decision.ok = False
            decision.class_decision.findings.append({
                "component": "class", "relation": "self-address", "ok": False,
                "detail": f"declaration re-addresses to {class_address[:12]}, receipt "
                          f"records {str(class_decl.get('address'))[:12]}",
            })

        # Coverage is re-run at verification, not only at issuance: a receipt is
        # read by people who did not watch it being written.
        covered, problems = covered_by(cls, class_decl.get("exercised_members", {}))
        if not covered:
            decision.ok = False
            decision.class_decision.ok = False
            decision.class_decision.findings.append({
                "component": "evidence", "relation": "covered_by", "ok": False,
                "detail": "; ".join(problems),
            })
        match = decision.ok

    return VerificationResult(
        signature_valid=sig_ok,
        configuration_match=match,
        receipt_approved=receipt.approved,
        approved_address=receipt.configuration_address,
        runtime_address=runtime_manifest.configuration_address,
        diff=diff or {},
        trust_anchored=anchored,
        class_decision=decision,
        class_address=class_address,
    )


def audit_event(receipt: Receipt, manifest: Manifest, action: str, principal: str) -> dict[str, Any]:
    """The runtime log line that makes the auditor's questions answerable.

    Four questions, each answerable from this one record plus the receipt:
    which configuration acted, was it evaluated, was the eval set clean, did
    anything change afterwards.
    """
    return {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "principal": principal,
        "action": action,
        "agent": receipt.payload["agent"],
        "release": receipt.payload["release"]["label"],
        "receipt": receipt.address(),
        "configuration": manifest.configuration_address,
        "tools": manifest.components["tools"].address,
        "model": manifest.components["model"].detail.get("id"),
    }
