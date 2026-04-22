# Header Manipulation — Usurpation de Referer et User-Agent

## Faille
Manipulation des en-têtes HTTP (Referer & User-Agent spoofing)

## Catégorie OWASP
A07:2021 — Identification and Authentication Failures

## Comment trouver la faille

1. Sur la page d'accueil, en bas dans le footer, on remarque un lien sur "© BornToSec"
   qui pointe vers une page avec un hash SHA-256 dans l'URL :
   `?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

2. En accédant à cette page et en inspectant le code source HTML, on trouve deux
   commentaires HTML cachés (enfouis au milieu de centaines de lignes vides) :
   - `You must come from : "https://www.nsa.gov/".`
   - `Let's use this browser : "ft_bornToSec".`

3. Ces indices indiquent que le serveur vérifie les en-têtes HTTP `Referer` et `User-Agent`.

## Exploitation

```bash
curl -H "Referer: https://www.nsa.gov/" \
     -H "User-Agent: ft_bornToSec" \
     "http://<IP>/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f"
```

Le serveur vérifie que :
- Le Referer est "https://www.nsa.gov/"
- Le User-Agent est "ft_bornToSec"

Si les deux conditions sont remplies, le flag est affiché.

## Flag
`f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

## Comment corriger

1. **Ne jamais se fier aux en-têtes HTTP pour l'authentification ou le contrôle d'accès.**
   Le Referer et le User-Agent sont entièrement contrôlés par le client et peuvent être
   falsifiés à volonté avec un simple curl ou un plugin navigateur.

2. **Utiliser des mécanismes d'authentification robustes** : tokens de session côté serveur,
   JWT signés, ou authentification multi-facteurs.

3. **Ne pas cacher des informations sensibles dans les commentaires HTML.** Les commentaires
   sont visibles par n'importe qui via "Afficher le code source". Toute logique de sécurité
   doit rester côté serveur.
