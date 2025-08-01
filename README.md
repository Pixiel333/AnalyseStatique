# Analyseur PE Complet

Ce projet est un script Python d'analyse complète de fichiers PE (Portable Executable) sous Windows.  
Il propose plusieurs options pour analyser l'entropie, les ressources, les imports, les sections, les chaînes, les hashs et scanner avec des règles YARA.

---

## Prérequis

- Python 3.x installé
- `pip3` pour gérer les paquets Python
- `yara-python` pour l’analyse YARA
- `pefile` pour l’analyse des fichiers PE

---

## Installation

1. **Cloner le dépôt :**

```bash
git clone https://github.com/Pixiel333/AnalyseStatique.git
cd AnalyseStatique
````

2. **Créer un environnement virtuel Python :**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Installer les dépendances :**

```bash
pip3 install -r requirements.txt
```
---

## Utilisation

Lancez le script principal avec l’option `-i` pour spécifier le fichier PE à analyser, et choisissez les options d’analyse souhaitées :

```bash
python3 analyse.py -i <fichier_PE> [options]
```

### Options disponibles :

| Option            | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| `-i, --input`     | **(Obligatoire)** Chemin vers le fichier PE                     |
| `-e, --entropy`   | Affiche l’entropie et détecte un packer                         |
| `-r, --resources` | Liste les types et nombres de ressources                        |
| `-f, --functions` | Liste les DLL et fonctions importées                            |
| `-s, --sections`  | Liste les sections et leurs tailles                             |
| `-a, --all`       | Effectue toutes les analyses sauf DIE                           |
| `-t, --strings`   | Extrait les chaînes et filtre URLs, IP, domaines, DLL, binaires |
| `--die`           | Lance DIE et affiche son résultat (doit être installé)          |
| `-H, --hash`      | Calcule MD5, SHA1, SHA256, SHA512                               |
| `-y, --yara`      | Scanne avec les règles YARA locales                             |

---

## Exemple

Pour analyser un fichier avec toutes les options sauf DIE :

```bash
python3 analyse.py -i samples/malware.exe -a
```

Pour scanner uniquement avec YARA :

```bash
python3 analyse.py -i samples/malware.exe -y
```

---

## Remarques

* L’option `--die` nécessite que l’outil DIE soit installé et disponible dans votre PATH.
* Le dossier `yara_rules` doit contenir vos règles YARA pour le scan.
* L’environnement virtuel est recommandé pour éviter les conflits de dépendances.

---


## Auteur

Pixiel333
