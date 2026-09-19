"""Canonical serialization under *declared* equivalence profiles.

EvalSeal never says "the canonical form". It says "the canonical form under
profile P", and P travels inside the signed receipt. That is the whole point:
before you hash anything you have to declare what `same` means, and different
jobs need different answers.

Three profiles ship here (`strict`, `eval`, `integral_safe`).

``strict`` -- the identity relation, used for configuration addressing
    (prompts, tool definitions, procedures, model ids). Collapses only
    transformations that a serializer, formatter or transport can introduce
    without a human editing anything:
      * object key ordering
      * insignificant whitespace between JSON tokens
      * string escape form (``\\u00e9`` vs the literal character)
      * Unicode composition form (NFD -> NFC)
    Everything else changes the address, including ``1`` vs ``1.0``, because a
    schema that says integer and a schema that says float are different
    contracts.

``eval`` -- the evaluation-equivalence relation, used for leakage detection.
    Everything ``strict`` collapses, plus:
      * numeric form (``1``, ``1.0``, ``1e0`` all collapse)
      * leading/trailing and runs of interior whitespace inside strings
    This is deliberately looser. It is the right relation for "is this
    held-out item already in my training corpus", and the wrong relation for
    "is this the tool definition I approved".

Both profiles apply NFC. NFC is not confusable folding: a Cyrillic `а`
substituted for a Latin `a` survives NFC and therefore changes the address
under both profiles. ``tests/test_identity.py`` pins that behaviour, because a
homoglyph edit to a tool description is exactly the attack an identity
relation must not absorb.

Relation to RFC 8785 (JCS): ``eval`` is JCS number handling plus NFC plus
string whitespace folding. ``strict`` is deliberately *not* JCS -- JCS follows
ECMAScript number semantics, under which ``1.0`` serializes as ``1``, and that
collapse is unsafe for schema identity. Neither profile claims byte
compatibility with any other addressing scheme; see ``address.py``.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, asdict
from typing import Any

__all__ = ["Profile", "PROFILES", "canonicalize", "canonical_text",
           "profile_declaration", "Inadmissible", "SAFE_INTEGER"]

_WS_RUN = re.compile(r"\s+")

# Characters that MUST be escaped in a JSON string, mapped to their shortest
# legal escape (RFC 8785 section 3.2.2.2).
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


SAFE_INTEGER = 9007199254740991          # 2**53 - 1


class Inadmissible(ValueError):
    """A value outside the relation's declared domain.

    Raised rather than answered. A relation that silently approximates a value
    it cannot represent gives a confident wrong answer; refusing is the only
    safe third option, and it is what makes the relation portable to a
    reimplementation in a language without arbitrary-precision integers.
    """


@dataclass(frozen=True)
class Profile:
    """A declared equivalence relation.

    Every flag is named and reported, so a reader can see exactly which
    transformations are being treated as meaning-preserving.
    """

    name: str
    sort_keys: bool = True
    nfc: bool = True
    # True  -> ECMAScript/JCS number semantics; 1.0 and 1 collapse.
    # False -> int and float are distinct lexical regimes; 1.0 and 1 differ.
    collapse_numeric_form: bool = False
    # Strip and collapse interior whitespace runs inside string values.
    fold_string_whitespace: bool = False
    # Normalise CRLF/CR to LF inside string values (a transport artifact).
    normalize_newlines: bool = True
    # Admission rule: accept only integral values within +/- (2**53 - 1), and
    # REJECT everything else rather than approximating it. Under this rule any
    # spelling of an integral value is the same value (1 == 1.0), and a number
    # a float64 reimplementation could not round-trip is refused at addressing
    # time instead of being silently corrupted downstream.
    integral_safe: bool = False

    def describe(self) -> dict[str, Any]:
        return asdict(self)


PROFILES: dict[str, Profile] = {
    "strict": Profile(
        name="strict",
        collapse_numeric_form=False,
        fold_string_whitespace=False,
    ),
    "eval": Profile(
        name="eval",
        collapse_numeric_form=True,
        fold_string_whitespace=True,
    ),
    # A third declared position, not a compromise between the other two. It
    # treats numeric *spelling* as insignificant for integral values and refuses
    # anything it cannot represent exactly. Whether that is right depends on
    # whether the JSON type of a schema bound is part of the contract -- see the
    # bake-off, which measures the disagreement instead of settling it by
    # assertion.
    "integral_safe": Profile(
        name="integral_safe",
        collapse_numeric_form=True,
        fold_string_whitespace=False,
        integral_safe=True,
    ),
}


def profile_declaration(profile: str | Profile) -> dict[str, Any]:
    """The machine-readable declaration that gets embedded in a receipt."""
    p = _resolve(profile)
    return p.describe()


def _resolve(profile: str | Profile) -> Profile:
    if isinstance(profile, Profile):
        return profile
    try:
        return PROFILES[profile]
    except KeyError:
        raise ValueError(
            f"unknown profile {profile!r}; declared profiles are {sorted(PROFILES)}"
        ) from None


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------

def _norm_string(s: str, p: Profile) -> str:
    if p.normalize_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
    if p.nfc:
        s = unicodedata.normalize("NFC", s)
    if p.fold_string_whitespace:
        s = _WS_RUN.sub(" ", s).strip()
    return s


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _SHORT_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            # Everything else is emitted literally; the result is UTF-8 encoded
            # at the end. This is what makes escape form non-significant.
            out.append(ch)
    out.append('"')
    return "".join(out)


# --------------------------------------------------------------------------
# numbers
# --------------------------------------------------------------------------

def _es_number(x: float | int) -> str:
    """ECMAScript Number::toString, which is what JCS mandates."""
    if isinstance(x, bool):  # bool is an int subclass; caller handles it first
        raise TypeError("bool is not a number here")
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not representable in JSON")
    if x == 0:
        return "0"  # collapses -0.0, per JCS
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    # Python spells small/large exponents the same way ES does, modulo the
    # exponent sign which Python already includes ('1e+21', '1e-07' vs ES
    # '1e+21', '1e-7'). Trim the zero padding ES does not emit.
    if "e" in r:
        mantissa, exp = r.split("e")
        sign = "+" if not exp.startswith("-") else "-"
        exp = exp.lstrip("+-").lstrip("0") or "0"
        r = f"{mantissa}e{sign}{exp}"
    return r


def _integral_safe_number(x: float | int, path: str) -> str:
    """Integral values within the safe range, in one spelling. Everything else refused."""
    if isinstance(x, float):
        if math.isnan(x) or math.isinf(x):
            raise Inadmissible(f"NaN/Infinity is not admissible at {path or '/'}")
        if x != int(x):
            raise Inadmissible(
                f"non-integral value {x!r} at {path or '/'} is outside the declared domain; "
                "declare a relation that admits floats, or keep the field out of the "
                "material set"
            )
        x = int(x)
    if abs(x) > SAFE_INTEGER:
        raise Inadmissible(
            f"integer {x} at {path or '/'} exceeds the safe integral range "
            f"(+/- {SAFE_INTEGER}); it cannot be round-tripped through float64, so it is "
            "refused rather than approximated"
        )
    return str(x)


def _typed_number(x: float | int) -> str:
    """Number form that keeps the int/float distinction visible.

    ``1`` -> ``1``;  ``1.0`` -> ``1.0``;  ``1e0`` -> ``1.0``.
    """
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not representable in JSON")
    r = repr(float(x))
    if "e" not in r and "." not in r:
        r += ".0"
    return r


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------

def _emit(obj: Any, p: Profile, out: list[str], path: str) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, str):
        out.append(_escape_string(_norm_string(obj, p)))
    elif isinstance(obj, (int, float)):
        if p.integral_safe:
            out.append(_integral_safe_number(obj, path))
        else:
            out.append(_es_number(obj) if p.collapse_numeric_form else _typed_number(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, item in enumerate(obj):
            if i:
                out.append(",")
            _emit(item, p, out, f"{path}[{i}]")
        out.append("]")
    elif isinstance(obj, dict):
        items = list(obj.items())
        for k, _ in items:
            if not isinstance(k, str):
                raise TypeError(f"non-string object key at {path}: {k!r}")
        # Two distinct source keys can normalise to the same string -- an NFC and
        # an NFD spelling of the same word, or (under whitespace folding) "a b"
        # and "a  b". Emitting both would produce a duplicate key, whose meaning
        # depends on which one the reader keeps, and would give two genuinely
        # different mappings the same address. That is a false accept, so the
        # object is refused instead.
        normalised = [_norm_string(k, p) for k, _ in items]
        if len(set(normalised)) != len(normalised):
            seen: dict[str, str] = {}
            for original, norm in zip((k for k, _ in items), normalised):
                if norm in seen:
                    raise Inadmissible(
                        f"keys {seen[norm]!r} and {original!r} at {path or '/'} both "
                        f"normalise to {norm!r} under profile {p.name!r}; the object has "
                        "no unambiguous canonical form and is refused rather than "
                        "collapsed into a duplicate key"
                    )
                seen[norm] = original
        if p.sort_keys:
            # RFC 8785: sort by UTF-16 code unit sequence, not by code point.
            items.sort(key=lambda kv: _norm_string(kv[0], p).encode("utf-16-be"))
        out.append("{")
        for i, (k, v) in enumerate(items):
            if i:
                out.append(",")
            out.append(_escape_string(_norm_string(k, p)))
            out.append(":")
            _emit(v, p, out, f"{path}/{k}")
        out.append("}")
    else:
        raise TypeError(f"not JSON-representable at {path}: {type(obj).__name__}")


def canonicalize(obj: Any, profile: str | Profile = "strict") -> bytes:
    """Serialize ``obj`` to the canonical UTF-8 bytes of ``profile``."""
    p = _resolve(profile)
    out: list[str] = []
    _emit(obj, p, out, "")
    return "".join(out).encode("utf-8")


def canonical_text(text: str, profile: str | Profile = "strict") -> bytes:
    """Canonical bytes for a free-text artifact (a prompt, a procedure).

    Text has no key ordering to fix, so this applies only the string-level
    rules of the profile, plus a single trailing newline so that "file ends
    with a newline" is not a material change.
    """
    p = _resolve(profile)
    s = _norm_string(text, p)
    if not p.fold_string_whitespace:
        # strict: trailing whitespace at end of file is a formatter artifact,
        # interior whitespace is content.
        s = s.rstrip("\n \t") + "\n"
    return s.encode("utf-8")
