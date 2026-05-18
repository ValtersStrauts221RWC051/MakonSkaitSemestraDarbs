"""
Feature order (must match exactly):
  [0] dns_domain_name_length
  [1] dns_subdomain_name_length
  [2] numerical_percentage
  [3] character_entropy
  [4] max_continuous_numeric_len
  [5] max_continuous_alphabet_len
  [6] max_continuous_consonants_len
  [7] max_continuous_same_alphabet_len
  [8] vowels_consonant_ratio
  [9] conv_freq_vowels_consonants

Each feature is computed over the **full domain name including the trailing dot**
(e.g. "google.com." has length 11, not 10). This convention matches the Kaggle
training CSVs and is critical for correct scoring.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import onnxruntime as ort

VOWELS = frozenset("aeiou")
ALPHA = frozenset("abcdefghijklmnopqrstuvwxyz")
CONSONANTS = ALPHA - VOWELS

# Feature order in the ONNX graph — DO NOT REORDER.
FEATURE_NAMES = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "numerical_percentage",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
]

INFO_LINE_RE = re.compile(r"^\[INFO\]\s+(\{.*\})\s*$")


# ----------------------------------------------------------------------------
# Domain canonicalization
# ----------------------------------------------------------------------------

def canonical_name(raw_name: str) -> str:
    """Return the domain with a guaranteed trailing dot.

    The training CSV convention always includes the root dot, e.g.
    "google.com." has length 11. We append one if missing so length-based
    features land in the same distribution as the training data.

        >>> canonical_name("google.com")
        'google.com.'
        >>> canonical_name("google.com.")
        'google.com.'
    """
    return raw_name if raw_name.endswith(".") else raw_name + "."


def subdomain_part(name: str) -> str:
    """Everything left of the registrable domain (2LD.TLD), no trailing dot.

    Algorithm: strip the trailing root dot, split on `.`, drop the last two
    labels (TLD + 2LD), rejoin with `.`. Returns "" for bare apex domains.

        >>> subdomain_part("a.b.c.example.com.")
        'a.b.c'
        >>> subdomain_part("example.com.")
        ''
        >>> subdomain_part("iqm35.o4ga.t.lab-c2.local.")
        'iqm35.o4ga.t'
    """
    n = name.rstrip(".")
    parts = n.split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


# ----------------------------------------------------------------------------
# Feature extractors  (one function per ML feature, each with formula + example)
# ----------------------------------------------------------------------------

def f_dns_domain_name_length(full: str) -> float:
    """[0] Total length of the canonical domain name (including the trailing dot).

    Formula:  len(full)

        >>> f_dns_domain_name_length("google.com.")
        11.0
    """
    return float(len(full))


def f_dns_subdomain_name_length(full: str) -> float:
    """[1] Length of the subdomain portion (everything left of the 2LD.TLD).

    Formula:  len(subdomain_part(full))
    Tunnels typically have very long subdomains (60+ chars) carrying encoded
    payload; benign domains rarely exceed ~20.

        >>> f_dns_subdomain_name_length("api.cdn.google.com.")
        7.0      # "api.cdn"
    """
    return float(len(subdomain_part(full)))


def f_numerical_percentage(full: str) -> float:
    """[2] Fraction of characters that are decimal digits.

    Formula:  count(ch.isdigit() for ch in full) / len(full)
    Hex- and base32-encoded tunneling payloads push this up; plain English
    domains sit near 0.

        >>> f_numerical_percentage("4gamers.co.th.")     # 1 digit / 14
        0.07142857142857142
    """
    if not full:
        return 0.0
    return sum(ch.isdigit() for ch in full) / len(full)


def f_character_entropy(full: str) -> float:
    """[3] Shannon entropy over the raw character distribution (base 2).

    Formula:  -Σ p(c) * log2(p(c))  where p(c) = count(c) / len(full)
    Random-looking encoded payloads have high entropy (≥ 4.5 bits); short
    repetitive domains like "google.com." have low entropy (~2.6 bits).

        >>> round(f_character_entropy("google.com."), 4)
        2.6635
    """
    if not full:
        return 0.0
    n = len(full)
    return -sum((c / n) * math.log2(c / n) for c in Counter(full).values())


def _max_run(s: str, predicate) -> int:
    """Length of the longest contiguous run of characters satisfying `predicate`."""
    best = cur = 0
    for ch in s:
        if predicate(ch):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def f_max_continuous_numeric_len(full: str) -> float:
    """[4] Longest run of consecutive digit characters.

    Formula:  longest contiguous run where ch.isdigit() is true.
    Encoded chunks like hex blobs produce long digit runs.

        >>> f_max_continuous_numeric_len("a6c10102dfc33abe.example.com.")
        4.0      # "0102"
    """
    return float(_max_run(full, str.isdigit))


def f_max_continuous_alphabet_len(flower: str) -> float:
    """[5] Longest run of consecutive a-z letters (input must be lowercased).

    Formula:  longest contiguous run where ch ∈ {a..z}.
    Benign domains have long uninterrupted letter runs; digit-interleaved
    tunneling payloads break runs into shorter chunks.

        >>> f_max_continuous_alphabet_len("google.com.")
        6.0      # "google"
    """
    return float(_max_run(flower, lambda c: c in ALPHA))


def f_max_continuous_consonants_len(flower: str) -> float:
    """[6] Longest run of consecutive consonants (b-d, f-h, j-n, p-t, v-z).

    Formula:  longest contiguous run where ch ∈ {consonants}.
    Random base32 payloads often produce unnaturally long consonant runs.

        >>> f_max_continuous_consonants_len("strength.com.")
        4.0      # "stre" no — "strn" actually: s,t,r are cons; "e" breaks → 3; "ngth" = 4
    """
    return float(_max_run(flower, lambda c: c in CONSONANTS))


def f_max_continuous_same_alphabet_len(flower: str) -> float:
    """[7] Longest run of the same character repeated.

    Formula:  longest contiguous run where s[i] == s[i+1].

        >>> f_max_continuous_same_alphabet_len("aaabcc.")
        3.0      # "aaa"
    """
    if not flower:
        return 0.0
    best = cur = 1
    for a, b in zip(flower, flower[1:]):
        if a == b:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 1
    return float(best)


def f_vowels_consonant_ratio(flower: str) -> float:
    """[8] Vowel-to-consonant count ratio.

    Formula:  count(vowels) / count(consonants)    (returns vowel count if no consonants)
    Natural language clusters around 0.4 - 0.7. Random encoded strings drift
    away (especially low when payload is mostly consonants like base32).

        >>> round(f_vowels_consonant_ratio("google.com."), 4)
        0.8
    """
    v = sum(1 for ch in flower if ch in VOWELS)
    c = sum(1 for ch in flower if ch in CONSONANTS)
    if c == 0:
        return float(v)
    return v / c


def f_conv_freq_vowels_consonants(flower: str) -> float:
    """[9] Vowel↔consonant transition frequency (matches training CSV convention).

    Formula:  count(v→c or c→v transitions over alpha-only sequence) / (len(full) - 1)
    Numerals and other non-alpha chars are skipped when counting transitions
    but the denominator is the FULL domain length minus one.

    This is normalized (not a raw count) — the un-normalized version produces
    out-of-distribution values that drive the model output to 0.

        >>> round(f_conv_freq_vowels_consonants("use.typekit.net."), 4)
        0.6
    """
    prev = None
    transitions = 0
    for ch in flower:
        cat = "v" if ch in VOWELS else ("c" if ch in CONSONANTS else None)
        if cat is None:
            continue
        if prev is not None and cat != prev:
            transitions += 1
        prev = cat
    denom = len(flower) - 1
    return transitions / denom if denom > 0 else 0.0


# ----------------------------------------------------------------------------
# Vector assembly
# ----------------------------------------------------------------------------

def extract_features(raw_name: str) -> np.ndarray:
    """Compute the 10-feature vector for a single domain.

    Returns a float32 ndarray of shape (10,) in `FEATURE_NAMES` order.
    """
    full = canonical_name(raw_name)
    flower = full.lower()
    return np.array(
        [
            f_dns_domain_name_length(full),
            f_dns_subdomain_name_length(full),
            f_numerical_percentage(full),
            f_character_entropy(full),
            f_max_continuous_numeric_len(full),
            f_max_continuous_alphabet_len(flower),
            f_max_continuous_consonants_len(flower),
            f_max_continuous_same_alphabet_len(flower),
            f_vowels_consonant_ratio(flower),
            f_conv_freq_vowels_consonants(flower),
        ],
        dtype=np.float32,
    )


# ----------------------------------------------------------------------------
# Log parsing & inference loop
# ----------------------------------------------------------------------------

def parse_log_line(line: str) -> dict | None:
    """Parse a CoreDNS `[INFO] {json}` line; return None for non-matching lines."""
    m = INFO_LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def get_name(entry: dict) -> str:
    return entry.get("name") or entry.get("query_name") or ""


def get_type(entry: dict) -> str:
    return entry.get("type") or entry.get("query_type") or ""


def iter_input(path: str | None):
    if path:
        with open(path) as f:
            yield from f
    else:
        yield from sys.stdin


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="model.onnx", help="path to ONNX model")
    ap.add_argument("--threshold", type=float, default=0.5, help="decision threshold for 'malicious'")
    ap.add_argument("--batch", type=int, default=256, help="rows per ONNX call")
    ap.add_argument("input", nargs="?", help="log file path; reads stdin if omitted")
    args = ap.parse_args()

    sess = ort.InferenceSession(args.model, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name
    out_name = sess.get_outputs()[0].name

    buf_features: list[np.ndarray] = []
    buf_meta: list[tuple[str, str]] = []  # (qtype, qname) for printing

    def flush():
        if not buf_features:
            return
        batch = np.stack(buf_features)
        probs = sess.run([out_name], {in_name: batch})[0]
        for (qtype, qname), p in zip(buf_meta, probs):
            label = "malicious" if p >= args.threshold else "benign"
            print(f"{label:>10}  p={float(p):.4f}  {qtype:>6}  {qname}")
        buf_features.clear()
        buf_meta.clear()

    for line in iter_input(args.input):
        entry = parse_log_line(line)
        if entry is None:
            continue
        name = get_name(entry)
        if not name:
            continue
        buf_features.append(extract_features(name))
        buf_meta.append((get_type(entry), name))
        if len(buf_features) >= args.batch:
            flush()
    flush()


if __name__ == "__main__":
    main()
