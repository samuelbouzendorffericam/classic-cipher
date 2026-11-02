#!/usr/bin/env python3
"""classic_ciphers : chiffres classiques (César, Vigenère) et analyse de fréquences.

Outil pédagogique pour comprendre les bases de la cryptanalyse (utile en CTF).
ATTENTION : ces chiffres sont cassés depuis des siècles, ne les utilisez jamais
pour protéger de vraies données. Pour cela : AES, ChaCha20, bibliothèques éprouvées.
"""
import argparse
import sys
import unicodedata
from collections import Counter

# Fréquences moyennes des lettres (en %) dans un texte français / anglais.
FREQ = {
    "fr": dict(zip("abcdefghijklmnopqrstuvwxyz", [
        7.64, 0.90, 3.26, 3.67, 14.72, 1.07, 0.87, 0.74, 7.53, 0.61, 0.05, 5.46, 2.97,
        7.10, 5.38, 3.02, 1.36, 6.55, 7.95, 7.24, 6.31, 1.63, 0.04, 0.43, 0.13, 0.33])),
    "en": dict(zip("abcdefghijklmnopqrstuvwxyz", [
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
        2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
        1.974, 0.074])),
}


def _is_ascii_letter(c: str) -> bool:
    return c.isascii() and c.isalpha()


def shift_char(c: str, k: int) -> str:
    if not _is_ascii_letter(c):
        return c
    base = ord("A") if c.isupper() else ord("a")
    return chr((ord(c) - base + k) % 26 + base)


def caesar(text: str, shift: int) -> str:
    """Chiffre de César : décale chaque lettre de `shift` (négatif pour déchiffrer)."""
    return "".join(shift_char(c, shift) for c in text)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    """Chiffre de Vigenère. La clé n'avance que sur les lettres du texte."""
    shifts = [ord(k.lower()) - ord("a") for k in key if _is_ascii_letter(k)]
    if not shifts:
        raise ValueError("La clé doit contenir au moins une lettre.")
    out, i = [], 0
    for c in text:
        if _is_ascii_letter(c):
            s = shifts[i % len(shifts)]
            out.append(shift_char(c, -s if decrypt else s))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def letter_counts(text: str) -> Counter:
    """Compte les lettres a-z (accents ignorés : é compte comme e)."""
    stripped = unicodedata.normalize("NFD", text.lower())
    return Counter(c for c in stripped if "a" <= c <= "z")


def frequencies(text: str) -> dict:
    counts = letter_counts(text)
    total = sum(counts.values())
    if total == 0:
        return {}
    return {letter: round(100 * counts[letter] / total, 2) for letter in sorted(counts)}


def chi_squared(text: str, lang: str = "fr") -> float:
    """Écart entre les fréquences du texte et celles de la langue (plus petit = mieux)."""
    counts = letter_counts(text)
    total = sum(counts.values())
    if total == 0:
        return float("inf")
    score = 0.0
    for letter, pct in FREQ[lang].items():
        expected = total * pct / 100
        score += (counts[letter] - expected) ** 2 / expected
    return score


def crack_caesar(text: str, lang: str = "fr", top: int = 3) -> list:
    """Teste les 26 décalages et classe les candidats par vraisemblance."""
    candidates = [(shift, caesar(text, -shift), chi_squared(caesar(text, -shift), lang))
                  for shift in range(26)]
    return sorted(candidates, key=lambda c: c[2])[:top]


def _read_text(arg_text):
    return arg_text if arg_text is not None else sys.stdin.read()


def main() -> None:
    parser = argparse.ArgumentParser(description="Chiffres classiques et analyse de fréquences.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("caesar", help="chiffre ou déchiffre avec César")
    p.add_argument("--shift", type=int, required=True)
    p.add_argument("--decrypt", action="store_true")
    p.add_argument("text", nargs="?")

    p = sub.add_parser("vigenere", help="chiffre ou déchiffre avec Vigenère")
    p.add_argument("--key", required=True)
    p.add_argument("--decrypt", action="store_true")
    p.add_argument("text", nargs="?")

    p = sub.add_parser("crack", help="casse un César par analyse de fréquences")
    p.add_argument("--lang", choices=sorted(FREQ), default="fr")
    p.add_argument("--top", type=int, default=3)
    p.add_argument("text", nargs="?")

    p = sub.add_parser("freq", help="affiche les fréquences des lettres")
    p.add_argument("text", nargs="?")

    args = parser.parse_args()
    text = _read_text(args.text)

    if args.command == "caesar":
        print(caesar(text, -args.shift if args.decrypt else args.shift))
    elif args.command == "vigenere":
        print(vigenere(text, args.key, args.decrypt))
    elif args.command == "crack":
        for shift, plain, score in crack_caesar(text, args.lang, args.top):
            print(f"décalage {shift:2d} (score {score:7.1f}) : {plain}")
    else:
        for letter, pct in sorted(frequencies(text).items(), key=lambda kv: -kv[1]):
            print(f"{letter} {pct:5.2f} % {'#' * round(pct)}")


if __name__ == "__main__":
    main()
