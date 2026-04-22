# Cookie Tampering — Manipulation du cookie I_am_admin

## Faille
Contrôle d'accès basé sur un cookie client modifiable, avec un hash MD5 prévisible.

## Catégorie OWASP
A01:2021 — Broken Access Control

## Comment trouver la faille

1. En ouvrant l'inspecteur du navigateur (onglet Stockage > Cookies), on observe un
   cookie nommé `I_am_admin` avec la valeur `68934a3e9455fa72420237eb05902327`.

2. Ce format (32 caractères hexadécimaux) correspond à un hash MD5.

3. En cherchant ce hash dans un décodeur MD5 (ou en testant les valeurs évidentes),
   on découvre que c'est le MD5 de "false" :
   `echo -n "false" | md5sum` → `68934a3e9455fa72420237eb05902327`

4. Le nom du cookie (`I_am_admin`) et sa valeur (`false`) suggèrent fortement qu'il
   faut le changer en `true`.

## Exploitation

1. Calculer le MD5 de "true" :
   `echo -n "true" | md5sum` → `b326b5062b2f0e69046810717534cb09`

2. Dans l'inspecteur du navigateur, modifier la valeur du cookie `I_am_admin` en :
   `b326b5062b2f0e69046810717534cb09`

3. Recharger la page. Le flag s'affiche.

## Flag
`df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`

## Comment corriger

1. **Ne jamais stocker de rôle ou de statut d'autorisation dans un cookie côté client.**
   Le contrôle d'accès doit être géré exclusivement côté serveur, via des sessions.

2. **Utiliser des sessions serveur** : stocker un identifiant de session dans le cookie
   et garder les données d'autorisation (admin ou non) dans la base de données ou
   en mémoire côté serveur.

3. **Si un cookie doit contenir des données, le signer cryptographiquement** (HMAC)
   pour détecter toute modification. MD5 n'est pas une signature — c'est un hash
   facilement réversible via des rainbow tables.

4. **Utiliser les flags de sécurité sur les cookies** : `HttpOnly`, `Secure`, `SameSite`.
