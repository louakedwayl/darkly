# Cookie Manipulation — Privilege Escalation

## Localisation
Page d'accueil — cookie `I_am_admin` présent dans les headers de réponse.

## Identification
Cookie observé via F12 > Application > Cookies :
I_am_admin = 68934a3e9455fa72420237eb05902327

32 caractères hexadécimaux → hash MD5.

## Crack du hash
echo -n "false" | md5sum → 68934a3e9455fa72420237eb05902327
Valeur initiale = md5("false")

## Exploitation
Remplacement du cookie par md5("true") :
b326b5062b2f0e69046810717534cb09

Flag affiché : df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3

## Impact
Élévation de privilège triviale. Aucune vérification serveur de
l'intégrité du cookie. Tout utilisateur peut forger son statut admin.

## Fix
- Ne jamais stocker d'état d'authentification/autorisation côté client
- Utiliser une session serveur : $_SESSION['is_admin'] = true
- Si cookie nécessaire : signer avec HMAC + secret serveur
- Vérifier la signature à chaque requête

## Catégorie OWASP
A01:2021 — Broken Access Control
