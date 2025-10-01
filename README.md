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

Windows (Powershell) :
```bash
python3 -m venv venv
.\venv\Scripts\Activate.ps1
```


3. **Installer les dépendances :**

```bash
pip3 install -r requirements.txt
```
---

## Utilisation

Utilisez `-i` pour spécifier le fichier. Si aucune autre option n’est précisée, toutes les analyses seront lancées par défaut (hors DIE et YARA).

```bash
python3 analyse.py -i <fichier> [options]
```

### Options disponibles :

| Option            | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| `-i, --input`     | **(Obligatoire)** Chemin vers le fichier PE, MSI ou ZIP         |
| `-e, --entropy`   | Affiche l’entropie et détecte un packer                         |
| `-r, --resources` | Liste les types et nombres de ressources                        |
| `-f, --functions` | Liste les DLL et fonctions importées                            |
| `-s, --sections`  | Liste les sections et leurs tailles                             |
| `-t, --strings`   | Extrait les chaînes et filtre URLs, IP, domaines, DLL, binaires |
| `--die`           | Lance DIE et affiche son résultat (doit être installé)          |
| `--diegui`           | Lance DIE en mode graphique avec le fichier                     |
| `-H, --hash`      | Calcule MD5, SHA1, SHA256, SHA512                               |
| `-y, --yara`      | Scanne avec les règles YARA locales                             |
| `-o, --extract`   | Extrait les ressources dans un dossier (par défaut: output/resources) |

---

## Exemple

Pour analyser un fichier avec toutes les options sauf DIE et YARA :

```bash
python3 analyse.py -i path/to/app.exe
```

Pour scanner uniquement avec YARA :

```bash
python3 analyse.py -i path/to/app.exe -y
```

Pour afficher et extraire les ressources dans un dossier (par défaut: output/resources)) :

```bash
python3 analyse.py -i path/to/app.exe -o path/to/output
```

---

## Remarques

* L’option `--die` nécessite que l’outil DIE soit installé et disponible dans votre PATH.
* Le dossier `yara_rules` doit contenir vos règles YARA pour le scan.
* L’environnement virtuel est recommandé pour éviter les conflits de dépendances.

---


## Auteur

Pixiel333
