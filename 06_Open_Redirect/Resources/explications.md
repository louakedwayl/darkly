# Open Redirect — Redirection non validée

## Faille
Le paramètre `site` dans la page de redirection accepte n'importe quelle URL
sans validation, permettant de rediriger les utilisateurs vers un site malveillant.

## Catégorie OWASP
A01:2021 — Broken Access Control

## Comment trouver la faille

1. Dans le footer de chaque page, on trouve des liens vers les réseaux sociaux :
   - `index.php?page=redirect&site=facebook`
   - `index.php?page=redirect&site=twitter`
   - `index.php?page=redirect&site=instagram`

2. Le paramètre `site` contrôle la destination de la redirection.

3. En remplaçant la valeur par une URL externe arbitraire, le serveur redirige
   sans aucune vérification.

## Exploitation

```bash
curl -v "http://<IP>/index.php?page=redirect&site=https://evil.com"
```

Le serveur redirige l'utilisateur vers `https://evil.com` sans vérification.
Dans un scénario réel, un attaquant pourrait envoyer un lien comme :
`http://site-de-confiance.com/redirect?site=https://phishing-site.com`
La victime clique en confiance car le domaine initial est légitime.

## Flag
`b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`

## Comment corriger

1. **Utiliser une whitelist de destinations autorisées** : ne permettre la redirection
   que vers des URLs connues et approuvées (facebook.com, twitter.com, etc.).

2. **Ne pas passer l'URL complète en paramètre** : utiliser un identifiant
   (ex: `site=facebook`) et résoudre côté serveur vers l'URL correspondante
   via un mapping prédéfini.

3. **Valider l'URL de destination** : vérifier que le domaine cible fait partie
   d'une liste autorisée avant d'effectuer la redirection.

4. **Afficher une page d'avertissement** : "Vous allez être redirigé vers un
   site externe" avec un lien cliquable, plutôt qu'une redirection automatique.
