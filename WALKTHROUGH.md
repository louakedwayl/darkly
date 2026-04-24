# Darkly — Walkthrough complet

> Chronologie de ma progression sur les 14 breaches.
> Détails techniques dans chaque sous-dossier `XX_Breach_Name/Resources/`.

---

## Setup initial
- VM Darkly (i386) lancée
- Accès via navigateur
- Burp Suite en proxy

---

## Phase 1 — Reconnaissance initiale

### WhatWeb
$ whatweb 127.0.0.1:8080

Résultats clés :
- **PHP 5.5.9-1ubuntu4.29** (obsolète, multiples CVE)
- **nginx 1.4.6** (2014, très ancien)
- **Cookie suspect : I_am_admin** → piste immédiate d'élévation de privilège
- **JQuery, HTML5** → stack front classique

### Cartographie manuelle
Endpoints identifiés via navigation et Ctrl+U :
- Pages principales : `?page=survey`, `?page=member`, `?page=signin`
- Upload/search : `?page=upload`, `?page=searchimg`
- Feedback : `?page=feedback`
- Redirect : `?page=redirect&site=facebook` (param `site` → open redirect ?)
- Media : `?page=media&src=nsa` (param `src` → LFI ?)
- **Hash caché dans le footer** : `?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

---

## Breach #1 — Cookie Manipulation

**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `01_Cookie_Manipulation/`

### Résumé
Cookie `I_am_admin` = `68934a3e9455fa72420237eb05902327` = md5("false").
Cracké via CrackStation. Forge de md5("true") → flag affiché.

### Commandes clés
$ echo -n "false" | md5sum   → confirme md5(false)
$ echo -n "true"  | md5sum   → b326b5062b2f0e69046810717534cb09

→ Détail complet : `01_Cookie_Manipulation/Resources/description.md`

---

## Breach #2 — Hidden Page / Information Disclosure
**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `02_Hidden_Page/`

### Résumé
Lien caché dans le footer de `index.php` pointant vers une page "obscure" nommée avec un SHA-256 :
`?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

La page sert directement un `<script>alert('Good job! Flag : ...')</script>` en dur. Flag obtenu par simple clic.

### Faille exploitée
- **Security Through Obscurity** : le dev a cru cacher la page en la nommant avec un hash improbable.
- **Information Disclosure** : le lien est laissé visible dans le HTML du footer, accessible via Ctrl+U ou clic.

### Méthode
1. Ctrl+U sur la page d'accueil
2. Recherche de liens suspects dans le code source
3. Lien trouvé dans la balise `<ul class="copyright">` du footer
4. Clic → flag affiché via JS alert

### Règle violée
> L'URL n'est pas un secret. Toute ressource non protégée par authentification est publique.

---

---

## Phase 1 — Recon complétée

### robots.txt
$ curl http://127.0.0.1:8080/robots.txt

User-agent: *
Disallow: /whatever
Disallow: /.hidden

→ Deux chemins "cachés" révélés par le dev lui-même.

### /whatever/
- Listing de répertoire activé (Directory Listing enabled)
- Contient un seul fichier : `htpasswd`

### /.hidden/
- Listing de répertoire activé
- Contient 26 dossiers (un par lettre) + README
- Structure labyrinthique récursive → **rabbit hole** (à confirmer plus tard, mis en standby)
- README racine : "Tu veux de l'aide ? Moi aussi !" → troll
- Les 26 README de niveau 1 contiennent tous des indications contradictoires ("voisin de droite/gauche/dessus/dessous") → probablement destiné à faire perdre du temps

### sitemap.xml
- [ ] À tester

### Gobuster
- [ ] À lancer sur la racine pour couvrir les endpoints non listés

---

## Breach #3 — Directory Listing + Weak Password Storage
**Flag :** [à confirmer une fois les credentials utilisés au bon endroit]
**Dossier :** `03_Htpasswd_Crack/`

### Résumé
Exposition d'un fichier `htpasswd` via directory listing activé sur `/whatever/`.
Le fichier contient un couple `user:hash` avec un hash MD5 non salé, cracké en ligne.

### Méthode
1. Lecture de `robots.txt` → chemin `/whatever/` révélé
2. Accès au listing → fichier `htpasswd` visible
3. `curl http://127.0.0.1:8080/whatever/htpasswd` → `root:437394baff5aa33daa618be47b75cb49`
4. Identification du hash : 32 hexa = MD5
5. Crack via CrackStation → `437394baff5aa33daa618be47b75cb49` = `qwerty123@`
6. Vérification locale :
   $ echo -n "qwerty123@" | md5sum
   → 437394baff5aa33daa618be47b75cb49

### Failles cumulées
- **Security Misconfiguration** — Directory listing actif sur un répertoire contenant des secrets
- **Information Disclosure via robots.txt** — le dev a listé explicitement ses chemins sensibles
- **Cryptographic Failure** — hash MD5 non salé pour stocker un mot de passe
- **Weak Password** — "qwerty123@" cassable en < 1 seconde (présent dans rockyou.txt)

### Règles violées
> robots.txt n'est pas un mécanisme de sécurité. C'est une indication pour les crawlers, pas une protection d'accès.
> MD5 non salé ne doit jamais être utilisé pour stocker des mots de passe en 2026.

### TODO suite
Trouver **où** utiliser `root:qwerty123@` :
- [ ] Pas sur `?page=signin` (retourne WrongAnswer.gif)
- [ ] Tester en Basic Auth sur différents chemins (gobuster requis)
- [ ] Tester sur une éventuelle zone admin à découvrir

---

## État global
| # | Breach | Statut |
|---|---|---|
| 1 | Cookie Manipulation | ✅ Flag validé |
| 2 | Hidden Footer Page | ✅ Flag validé |
| 3 | Htpasswd Disclosure | 🟡 Credentials en main, destination à trouver |
| 4-14 | — | À explorer |

## Prochaines pistes à tester
- [ ] SQLi sur `?page=signin` (champs username/password)
- [ ] SQLi sur `?page=member` (Search Member)
- [ ] XSS stockée sur `?page=feedback`
- [ ] Path Traversal sur `?page=media&src=`
- [ ] Open Redirect sur `?page=redirect&site=`
- [ ] File Upload bypass sur `?page=upload`
- [ ] Gobuster full pour découvrir admin panel éventuel

---

## Breach #4 — Stored XSS
**Flag :** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
**Dossier :** `04_Stored_XSS/`

### Résumé
Injection d'un payload `<script>alert(...)</script>` dans un formulaire. Le serveur stocke et restitue l'input sans échappement → exécution du JS au rendu de la page.

### Méthode
1. Champ vulnérable identifié sur [PRÉCISE[ LE FORMULAIRE : feedback ? autre ?](http://localhost:8080/?page=feedback)]
2. Payload injecté : `<script>alert('XSS')</script>`
3. Submit
4. Au reload de la page, le script s'exécute → flag affiché

### Faille exploitée
- **Stored XSS (OWASP A03:2021 — Injection)**
- Absence de sanitization à l'entrée
- Absence d'output encoding à la sortie (pas de `htmlspecialchars()` côté PHP)

### Différence Stored vs Reflected
- **Reflected** : payload dans l'URL, exécuté une seule fois pour la victime cliquant le lien
- **Stored** : payload sauvegardé en base, exécuté pour **chaque visiteur** de la page → bien plus dangereux

### Contre-mesures
- `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` à l'affichage (PHP)
- Auto-escape dans React/Vue (déjà appliqué dans VoidTextile, Camagru)
- `Content-Security-Policy: script-src 'self'` pour bloquer les scripts inline
- Cookies `HttpOnly` pour empêcher le vol de session via XSS

---