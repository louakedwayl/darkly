# Data URI Injection — Injection via le paramètre src de la page media

## Faille
Le paramètre `src` de la page media est injecté directement dans l'attribut `data`
d'une balise `<object>` sans aucune validation, permettant l'injection de contenu
arbitraire via des data URIs.

## Catégorie OWASP
A03:2021 — Injection

## Comment trouver la faille

1. Sur la page d'accueil, on trouve un lien vers `?page=media&src=nsa` qui affiche
   une image NSA.

2. En inspectant le code source, on voit que le paramètre `src` est utilisé dans :
   ```html
   <object data="http://<IP>/images/nsa_prism.jpg"></object>
   ```

3. Le paramètre `src=nsa` est transformé en chemin d'image. Mais que se passe-t-il
   si on injecte une data URI à la place ?

## Exploitation

On encode un script JavaScript en base64 :
```bash
echo -n '<script>alert(1)</script>' | base64
# Résultat : PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

Puis on l'injecte via le paramètre `src` :
```bash
curl "http://<IP>/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
```

Le serveur insère la data URI directement dans la balise `<object data="...">`,
ce qui permet l'exécution de code arbitraire dans le navigateur.

## Flag
`928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d`

## Comment corriger

1. **Valider le paramètre `src` via une whitelist** : n'accepter que des valeurs
   prédéfinies (ex: `nsa`, `prism`) et les mapper côté serveur vers des chemins
   de fichiers connus.

2. **Interdire les data URIs** : rejeter toute valeur commençant par `data:`.

3. **Ne jamais insérer d'input utilisateur directement dans des attributs HTML**
   sans échappement. Utiliser `htmlspecialchars()` en PHP.

4. **Implémenter une Content Security Policy (CSP)** qui interdit les data URIs
   comme source de contenu : `Content-Security-Policy: default-src 'self'`.

5. **Valider le protocole** : n'accepter que `http://` et `https://` comme schémas
   dans les URLs.
