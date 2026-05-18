from __future__ import annotations

import math
from collections import Counter

VOWELS = frozenset("aeiou")
ALPHA = frozenset("abcdefghijklmnopqrstuvwxyz")
CONSONANTS = ALPHA - VOWELS

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


def canonical_name(raw_name: str) -> str:
    return raw_name if raw_name.endswith(".") else raw_name + "."


def subdomain_part(name: str) -> str:
    n = name.rstrip(".")
    parts = n.split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def parent_domain(name: str) -> str:
    n = name.rstrip(".")
    parts = n.split(".")
    if len(parts) < 2:
        return n
    return ".".join(parts[-2:])


def subdomain_depth(name: str) -> int:
    n = name.rstrip(".")
    if not n:
        return 0
    return n.count(".") + 1


def f_dns_domain_name_length(full: str) -> float:
    return float(len(full))


def f_dns_subdomain_name_length(full: str) -> float:
    return float(len(subdomain_part(full)))


def f_numerical_percentage(full: str) -> float:
    if not full:
        return 0.0
    return sum(ch.isdigit() for ch in full) / len(full)


def f_character_entropy(full: str) -> float:
    if not full:
        return 0.0
    n = len(full)
    return -sum((c / n) * math.log2(c / n) for c in Counter(full).values())


def _max_run(s: str, predicate) -> int:
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
    return float(_max_run(full, str.isdigit))


def f_max_continuous_alphabet_len(flower: str) -> float:
    return float(_max_run(flower, lambda c: c in ALPHA))


def f_max_continuous_consonants_len(flower: str) -> float:
    return float(_max_run(flower, lambda c: c in CONSONANTS))


def f_max_continuous_same_alphabet_len(flower: str) -> float:
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
    v = sum(1 for ch in flower if ch in VOWELS)
    c = sum(1 for ch in flower if ch in CONSONANTS)
    if c == 0:
        return float(v)
    return v / c


def f_conv_freq_vowels_consonants(flower: str) -> float:
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


def extract_features(raw_name: str) -> list[float]:
    full = canonical_name(raw_name)
    flower = full.lower()
    return [
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
    ]


def compute_features(query_name: str) -> dict[str, float]:
    values = extract_features(query_name)
    return dict(zip(FEATURE_NAMES, values))
