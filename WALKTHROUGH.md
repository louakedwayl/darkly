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
- 🟡 En cours : wordlist custom créée, scan à relancer avec `--exclude-length 975` (le serveur renvoie 200 sur toutes URLs inexistantes, taille fixe = page 404 déguisée par index.php)

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

## Breach #3 — Directory Listing + Weak Password Storage
**Flag :** [pas de flag direct — credentials récupérés et utilisés au breach #5]
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

---

## Breach #4 — Stored XSS
**Flag :** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
**Dossier :** `04_Stored_XSS/`

### Résumé
Injection d'un payload `<script>alert(...)</script>` dans un formulaire. Le serveur stocke et restitue l'input sans échappement → exécution du JS au rendu de la page.

### Méthode
1. Champ vulnérable identifié sur `?page=feedback`
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

## Breach #5 — Authentication Bypass via Credential Reuse
**Flag :** `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`
**Dossier :** `05_Admin_Auth/`

### Résumé
Découverte d'une zone admin `/admin/` accessible directement sans Basic Auth, contenant un formulaire de login. Les credentials récupérés au breach #3 (`root:qwerty123@`) sont valides → flag.

### Méthode
1. Découverte du chemin `/admin/` (test direct du chemin physique, hors routeur `?page=`)
2. Vérification : `curl http://127.0.0.1:8080/admin/` → renvoie le formulaire de login (200, pas de Basic Auth)
3. Soumission des creds htpasswd via POST :
   ```
   curl -X POST http://127.0.0.1:8080/admin/ \
     -d "username=root&password=qwerty123@&Login=Login" \
     -c cookies.txt -b cookies.txt -L
   ```
4. Réponse : `<h2>The flag is : d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff</h2>`

### Architecture défaillante observée
Deux systèmes de routing parallèles sur le même serveur :
- **`?page=X`** → routeur PHP custom via `index.php` (controllers internes)
- **`/admin/`** → chemin physique servi directement par nginx (dossier réel sur filesystem)

La zone `/admin/` est **isolée du routeur principal**, donc échappe aux éventuels middlewares de sécurité côté PHP. Cumul de fautes :
- Le htpasswd existe mais n'est **pas configuré dans nginx** pour protéger réellement le chemin
- Le formulaire PHP valide les creds en dur contre le **même couple** que celui exposé publiquement
- Aucun rate limiting, aucun lockout, aucune 2FA
- Typo dans le HTML (`recquired` au lieu de `required`) → indicateur de code amateur

### Failles cumulées
- **A07:2021 — Identification and Authentication Failures** (credential reuse, single factor)
- **A05:2021 — Security Misconfiguration** (htpasswd non appliqué côté serveur)
- **Defense in depth absent** : un seul couple user/pass protège tout, et il a déjà fuité

### Règle violée
> Une zone admin doit être protégée par plusieurs couches indépendantes (network ACL, Basic Auth serveur, auth applicative, 2FA). Réutiliser le même secret entre deux mécanismes annule l'effet de la défense en profondeur.

### Contre-mesures
- Activer la directive nginx `auth_basic` + `auth_basic_user_file` sur `/admin/`
- Stocker le htpasswd **hors du document root** (`/etc/nginx/.htpasswd` plutôt que `/var/www/html/whatever/`)
- Utiliser bcrypt/argon2 au lieu de MD5 dans le htpasswd (`htpasswd -B`)
- Implémenter rate limiting (`limit_req` nginx) sur les endpoints d'auth
- 2FA TOTP via lib comme RobThree/TwoFactorAuth

---

## État global
| # | Breach | Statut |
|---|---|---|
| 1 | Cookie Manipulation | ✅ Flag validé |
| 2 | Hidden Footer Page | ✅ Flag validé |
| 3 | Htpasswd Disclosure | ✅ Credentials exploités au #5 |
| 4 | Stored XSS | ✅ Flag validé |
| 5 | Admin Auth Bypass | ✅ Flag validé |
| 6-14 | — | À explorer |

**Score : 5/14**

---

## Prochaines pistes à tester (ordre de priorité)

### Priorité haute — ROI immédiat
- [ ] **SQLi sur `?page=signin`** : auth bypass classique (`admin'-- `, `' OR 1=1-- `)
- [ ] **SQLi UNION sur `?page=member`** (Search Member) : extraction via `information_schema`
- [ ] **Path Traversal sur `?page=media&src=`** : `../../../../etc/passwd`, `php://filter/convert.base64-encode/resource=index`

### Priorité moyenne
- [ ] **Open Redirect sur `?page=redirect&site=`** : tester URL externe arbitraire
- [ ] **File Upload bypass sur `?page=upload`** : extension/MIME/magic bytes
- [ ] **Reflected XSS sur `?page=searchimg`** : payload dans param de recherche

### Priorité basse / parallèle
- [ ] **Gobuster** : finir le scan avec `--exclude-length 975` pour mapper les chemins physiques restants
- [ ] **`.hidden/` parsing** : `wget -r` + grep récursif (bypass du rabbit hole textuel)
- [ ] **sitemap.xml** : vérification rapide

---

## Leçons techniques cumulées
1. **Reconnaissance d'abord** : `whatweb`, `robots.txt`, Ctrl+U, sitemap → toujours avant tout payload
2. **Deux systèmes de routing peuvent coexister** : routeur applicatif (`?page=`) vs filesystem (`/admin/`). Tester les deux.
3. **MD5 et SHA-1 sont morts** pour le stockage de mots de passe. CrackStation casse en secondes.
4. **Security through obscurity ≠ sécurité** : breach #2 et #5 démontrent que cacher un chemin n'est pas une protection.
5. **Credential reuse** = faille systémique. Un seul secret exposé compromet tous les systèmes qui le réutilisent.