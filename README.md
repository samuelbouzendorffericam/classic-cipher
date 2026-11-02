# classic-ciphers

Chiffres classiques (**César**, **Vigenère**) et **analyse de fréquences** en Python, pour comprendre les bases de la cryptographie et de la cryptanalyse (utile en CTF).

> Ces chiffres sont cassés depuis des siècles. Ils servent à apprendre, jamais à protéger de vraies données : pour cela, utilisez des algorithmes modernes (AES, ChaCha20) via des bibliothèques éprouvées.

## Utilisation

```bash
python3 classic_ciphers.py caesar --shift 3 "Hello, World!"
# Khoor, Zruog!

python3 classic_ciphers.py vigenere --key LEMON "ATTACKATDAWN"
# LXFOPVEFRNHR

python3 classic_ciphers.py crack --top 2 "Slz johaz kvytlua zby sl jhuhwé wlukhua xbl sh wsbpl avtil kvbjltlua"
python3 classic_ciphers.py freq "Un texte à analyser"
```

Exemple de cassage automatique d'un César (texte chiffré avec un décalage de 7, langue française) :

```
décalage  7 (score    12.3) : Les chats dorment sur le canapé pendant que la pluie tombe doucement
décalage 18 (score   152.8) : Ath rwpih sdgbtci hjg at rpcpeé etcspci fjt ap eajxt idbqt sdjrtbtci
```

Le texte peut aussi être passé sur l'entrée standard (`echo "..." | python3 classic_ciphers.py crack`).

## Concepts illustrés

- **Chiffrement par substitution** et pourquoi il laisse une empreinte statistique : la lettre la plus fréquente d'un texte français est `e`, même après chiffrement.
- **Analyse de fréquences** : on compare la distribution des lettres du texte à celle de la langue avec un test du χ² (plus le score est bas, plus le candidat est vraisemblable).
- Vigenère : la clé répétée masque les fréquences, mais pas pour toujours.

## Tests

```bash
python3 -m unittest -v
```

Les tests utilisent des valeurs de référence connues (`ATTACKATDAWN` / `LEMON` → `LXFOPVEFRNHR`).

## Limites

Le cassage automatique demande un texte d'une trentaine de lettres au moins et ne gère que le César, pas Vigenère.

## Pistes d'amélioration

- Casser Vigenère (test de Kasiski, indice de coïncidence).
- Ajouter le XOR à clé d'un octet, l'encodage Base64 et hexadécimal.
- Ajouter d'autres langues.

## Licence

MIT, voir [LICENSE](LICENSE).

---

*Réalisé avec l'aide de Claude (IA), relu et testé par l'auteur.*
