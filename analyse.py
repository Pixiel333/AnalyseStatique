import itertools
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import pefile
import argparse
import math
import hashlib
import re
import subprocess
import yara
import shutil
import mimetypes
import pymsi
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(encoding='utf-8')

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"
RESOURCE_TYPE = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST"
}
LANGUAGE_NAMES = {
    0x00: "NEUTRAL",
    0x01: "DEFAULT",
    0x09: "EN",
    0x0C: "FR",
    0x07: "DE",
    0x0A: "ES",
    0x10: "IT",
    0x11: "JA",
    0x04: "ZH",
    0x0E: "HU",
    0x19: "RU",
}
SUBLANGUAGE_NAMES = {
    0x00: "DEFAULT",
    0x01: "SYS_DEFAULT",
    0x02: "USER_DEFAULT"
}

def with_spinner(task_fn, message="Chargement..."):
    """
    Exécute une fonction avec un spinner animé tant qu'elle tourne.
    - task_fn: fonction à exécuter
    - message: texte affiché avant le spinner
    """
    stop_event = threading.Event()

    def spinner():
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if stop_event.is_set():
                break
            sys.stderr.write(f"\r{message} {c}")
            sys.stderr.flush()
            time.sleep(0.1)
        sys.stderr.write(f"\r{message} terminé !   \n")

    thread = threading.Thread(target=spinner)
    thread.start()

    try:
        result = task_fn()
    finally:
        stop_event.set()
        thread.join()

    return result
def is_pe(filepath):
    try:
        pe = pefile.PE(filepath)
        return True, pe
    except pefile.PEFormatError:
        return False, None

def extract_pe_from_zip(zip_path, tmp_dir):
    import zipfile, tempfile, os
    pe_files = []
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(tmp_dir)
    for root, _, files in os.walk(tmp_dir):
        for f in files:
            full_path = os.path.join(root, f)
            if f.lower().endswith((".exe", ".dll", ".sys")):
                try:
                    pefile.PE(full_path)
                    pe_files.append(full_path)
                except pefile.PEFormatError:
                    continue
    return pe_files

def extract_pe_from_msi(msi_path, tmp_dir):
    pe_files = []
    try:
        pkg = pymsi.package.Package(Path(msi_path))
        msi_obj = pymsi.msi.Msi(pkg, load_data=True)

        os.makedirs(tmp_dir, exist_ok=True)

        for file in msi_obj.files.values():
            if file.name.lower().endswith((".exe", ".dll", ".sys")):
                out_path = os.path.join(tmp_dir, file.name)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                
                if file.media is None:
                    continue
                cab_file = file.resolve()
                out_data = cab_file.decompress()
                
                with open(out_path, 'wb') as f:
                    f.write(out_data)

                try:
                    pefile.PE(out_path)
                    pe_files.append(out_path)
                except pefile.PEFormatError:
                    continue

        return pe_files

    except Exception as e:
        print(f"❌ Erreur lors de l'extraction du MSI: {e}")
        return []

def get_resource_type(entry):
    if entry.name is not None:
        return str(entry.name)
    return RESOURCE_TYPE.get(entry.struct.Id, f"ID:{entry.struct.Id}")

def get_lang_name(lang):
    return LANGUAGE_NAMES.get(lang, f"0x{lang:02X}")

def get_sublang_name(sublang):
    return SUBLANGUAGE_NAMES.get(sublang, f"0x{sublang:02X}")

def guess_extension(res_type):
    return {
        "ICON": "ico",
        "GROUP_ICON": "ico",
        "MANIFEST": "xml",
        "VERSION": "txt",
        "DIALOG": "bin",
        "RCDATA": "bin"
    }.get(res_type.upper(), "bin")

def analyze_resources(pe, output_dir=None):
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("❌ Aucune ressource trouvée.")
        return
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    print("📦 Ressources trouvées :")

    total = 0
    type_counter = defaultdict(int)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        res_type = get_resource_type(entry)

        if hasattr(entry, 'directory'):
            for res in entry.directory.entries:
                for lang_entry in res.directory.entries:
                    lang = lang_entry.data.lang if hasattr(lang_entry.data, 'lang') else 0
                    sublang = lang_entry.data.sublang if hasattr(lang_entry.data, 'sublang') else 0
                    lang_str = get_lang_name(lang)
                    sublang_str = get_sublang_name(sublang)

                    size = lang_entry.data.struct.Size
                    rva = lang_entry.data.struct.OffsetToData
                    data = pe.get_data(rva, size)

                    print(f"  - Type: {res_type} | Langue: {lang_str}/{sublang_str} | Taille: {size} octets | RVA: {hex(rva)}")

                    # Fichier de sortie
                    if output_dir:
                        filename = f"{res_type}_{type_counter[res_type]}.{guess_extension(res_type)}"
                        filepath = os.path.join(output_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(data)
                    type_counter[res_type] += 1
                    total += 1

    print(f"\n🔢 Nombre total de ressources : {total}")
    print("📊 Détail par type :")
    for k, v in type_counter.items():
        print(f"  - {k} : {v}")

def extract_resources(pe, output_dir):
    output_dir = output_dir
    analyze_resources(pe, output_dir)

    os.makedirs(output_dir, exist_ok=True)
    print("\n📦 Extraction des ressources...")


def collect_yara_rules_from_dirs(directories):
    rule_paths = {}
    for directory in directories:
        if directory.endswith("rules"):
            for file in os.listdir(directory):
                if file.endswith('.yar') or file.endswith('.yara'):
                    full_path = os.path.join(directory, file)
                    rule_name = os.path.splitext(file)[0]
                    rule_paths[rule_name] = full_path
        else:
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        full_path = os.path.join(root, file)
                        rule_name = os.path.splitext(file)[0]
                        rule_paths[rule_name] = full_path
    return rule_paths


def scan_with_yara(target_file, rules_dirs):
    print("Analyse avec les règles YARA...\n")
    try:
        rule_files = collect_yara_rules_from_dirs(rules_dirs)
        if not rule_files:
            print("⚠️  Aucune règle YARA trouvée dans les dossiers spécifiés.")
            return

        rules = yara.compile(
            filepaths=rule_files,
            externals={
                "filepath": target_file,
                "filename": os.path.basename(target_file),
                "extension": os.path.splitext(target_file)[1].lstrip('.').lower(),
                "filetype": mimetypes.guess_type(target_file)[0],
                "owner": "unknown_owner"
            }
        )

        matches = rules.match(target_file)

        seen = set()
        unique_matches = []
        for m in matches:
            if m.rule not in seen:
                seen.add(m.rule)
                unique_matches.append(m)

        if unique_matches:
            print(GREEN + f"✔️  {len(unique_matches)} règle(s) YARA ont matché :" + RESET)
            for match in unique_matches:
                print(RED + f" - {match.rule}" + RESET)
                if 'description' in match.meta:
                    print(f"      Description : {match.meta['description']}")
                elif 'info' in match.meta:
                    print(f"      Info : {match.meta['info']}")
                if 'reference' in match.meta:
                    print(BLUE + f"      Reference : {match.meta['reference']}" + RESET)
        else:
            print("❌  Aucune règle YARA n’a matché.")
    except yara.Error as e:
        print(RED + f"❌ Erreur lors du chargement YARA : {e}" + RESET)

def print_delimiter():
    width = shutil.get_terminal_size((80, 20)).columns
    print(f"\n{'-' * width}\n")

def calculate_entropy(data):
    if not data:
        return 0.0
    occurences = [0]*256
    for b in data:
        occurences[b] += 1
    entropy = 0
    length = len(data)
    for count in occurences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def get_hashes(filepath):
    hashes = {}
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
            sha512.update(data)

    hashes['md5'] = md5.hexdigest()
    hashes['sha1'] = sha1.hexdigest()
    hashes['sha256'] = sha256.hexdigest()
    hashes['sha512'] = sha512.hexdigest()
    return hashes

def extract_strings(data, min_length=4):
    candidate_strings = re.findall(rb'[\x20-\x7E]{' + bytes(str(min_length), 'ascii') + rb',}', data)
    clean_strings = []
    for s in candidate_strings:
        try:
            decoded = s.decode('utf-8', errors='ignore')
        except Exception:
            continue
        count_non_alnum = sum(
            1 for c in decoded if not c.isalnum() and not c.isspace() and c not in "-._:/\\"
        )
        if count_non_alnum / max(len(decoded), 1) > 0.3:
            continue
        clean_strings.append(decoded)
    return clean_strings

def get_functions(pe):
    functions = defaultdict(list)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
                functions[dll_name].append(func_name)
    return functions

def display_functions(functions):
    """Affiche les DLL et leurs fonctions."""
    print("DLL importées et fonctions associées :")
    for dll, funcs in functions.items():
        print(f"DLL: {dll}")
        print("Fonctions :")
        for func in funcs:
            print(f"  - {func}")

def display_dll_summary(functions):
    """Affiche juste la liste des DLL importées."""
    print("Résumé des DLL importées :")
    for dll in functions.keys():
        print(f"  - {dll}")

def filter_patterns(strings):
    urls = set()
    ips = set()
    domains = set()
    dlls = set()
    binaries = set()

    url_regex = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    ip_regex = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    )
    domain_regex = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(com|net|org|info|biz|co|io|gov|edu|fr|de|jp|cn|uk|us|ru|in|xyz|top|club|site|online|store|tech|me|tv|cc|app|dev|ai|mobi|name|pro|cloud|page|agency)\b',
        re.IGNORECASE
    )
    dll_regex = re.compile(r'\b[\w\-]+\.dll\b', re.IGNORECASE)
    bin_regex = re.compile(r'\b[\w\-]+\.(exe|bin|dat|sys|drv)\b', re.IGNORECASE)

    for s in strings:
        # URLs
        for match in url_regex.findall(s):
            urls.add(match)
        # IPs
        for match in ip_regex.findall(s):
            ips.add(match)
        # Domains
        for match in domain_regex.findall(s):
            domain_match = re.search(r'([a-zA-Z0-9\-\.]+\.' + match + r')\b', s, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1)
                if not any(domain in url for url in urls):
                    domains.add(domain)
        # DLLs
        for match in dll_regex.findall(s):
            dlls.add(match)
        # Binaries
        for match in bin_regex.findall(s):
            binaries.add(match)

    return {
        'urls': sorted(urls),
        'ips': sorted(ips),
        'domains': sorted(domains),
        'dlls': sorted(dlls),
        'binaries': sorted(binaries),
    }

def run_die(filepath):
    try:
        result = subprocess.run(['diec', '-r', '-d', '-u', '-U', filepath],capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"Erreur lors de l'exécution de DIE: {e}"

def run_die_gui(filepath):
        try:
            subprocess.Popen(['die', filepath])
            return "✔️ DIE GUI lancé."
        except FileNotFoundError:
            return "❌ DIE GUI introuvable (binaire 'die' non présent dans le PATH)."
        except Exception as e:
            return f"Erreur lors du lancement de DIE GUI: {e}"

def main():
    parser = argparse.ArgumentParser(description="Analyse PE complète avec options multiples")
    parser.add_argument("-i", "--input", required=True, help="Fichier PE à analyser")
    parser.add_argument("-e", "--entropy", action="store_true", help="Afficher l'entropie et détection pack")
    parser.add_argument("-r", "--resources", action="store_true", help="Lister les types et nombre de ressources")
    parser.add_argument("-f", "--functions", action="store_true", help="Lister les DLL et fonctions importées")
    parser.add_argument("-s", "--sections", action="store_true", help="Lister les sections et leurs tailles")
    parser.add_argument("-t", "--strings", action="store_true", help="Extraire strings et filtrer URLs, IP, domaines, dlls, binaires")
    parser.add_argument("--die", action="store_true", help="Lancer DIE et afficher son résultat (doit être installé)")
    parser.add_argument("--diegui", action="store_true", help="Lancer DIE en mode graphique avec le fichier PE")
    parser.add_argument("-H", "--hash", action="store_true", help="Calculer MD5, SHA1, SHA256, SHA512")
    parser.add_argument("-y", "--yara", action="store_true", help="Scanner avec les règles YARA locales")
    parser.add_argument("-o","--extract",nargs="?",const="output/resources",help="Extraire les ressources dans un dossier (par défaut: output/resources)")
    
    tmp_dir = tempfile.mkdtemp()
    args = parser.parse_args()
    if args.input and not any([args.entropy, args.resources, args.functions, args.sections, args.strings, args.hash, args.yara, args.die, args.extract, args.diegui]):
        args.entropy = True
        args.resources = True
        args.functions = True
        args.sections = True
        args.strings = True
        args.hash = True
    

    pe_files = []
    general_files = []
    input_path = args.input
    if input_path.lower().endswith('.zip'):
        pe_files = with_spinner(lambda: extract_pe_from_zip(input_path, tmp_dir), "Extraction du ZIP...")
        general_files = [os.path.join(tmp_dir, f) for f in os.listdir(tmp_dir) if not f.lower().endswith((".exe", ".dll", ".sys"))]
    elif input_path.lower().endswith('.msi'):
        tmp_msi_dir = os.path.join(tmp_dir, "msi_extracted")
        os.makedirs(tmp_msi_dir, exist_ok=True)
        pe_files = with_spinner(lambda: extract_pe_from_msi(input_path, tmp_msi_dir), "Extraction du MSI...")
        general_files = []
        for root, _, files in os.walk(tmp_msi_dir):
            for f in files:
                full_path = os.path.join(root, f)
                if not f.lower().endswith((".exe", ".dll", ".sys")):
                    general_files.append(full_path)
    else:
        is_pe_file, pe = with_spinner(lambda: is_pe(input_path), "Chargement du fichier...")
        if is_pe_file:
            pe_files = [input_path]
        else:
            general_files = [input_path]

    for pe_file in pe_files:
        print(f"\n\n{YELLOW}=== Analyse du PE: {pe_file} ==={RESET}\n")
        try:
            pe = pefile.PE(pe_file)
        except pefile.PEFormatError:
            print(f"❌ Impossible de charger le fichier PE: {pe_file}")
            continue
        if args.entropy:
            with open(pe_file, "rb") as f:
                data = f.read()
            entropy = with_spinner(lambda: calculate_entropy(data), "Calcul de l'entropie...")
            print(f"Entropie globale du fichier: {entropy:.2f}")
            if entropy > 7.0:
                print("Le fichier semble packé (entropie élevée).")
            else:
                print("Le fichier ne semble pas packé (entropie normale).")

        if args.resources:
            with_spinner(lambda: analyze_resources(pe), "Analyse des ressources...")
            print("Analyse des ressources terminée.")
            print_delimiter()

        if args.extract:
            output_dir = args.extract if args.extract != "output/resources" else "output/resources"
            with_spinner(lambda:extract_resources(pe, output_dir), f"Extraction des ressources vers {output_dir}...")
            print(f"Extraction des ressources terminée. Fichiers extraits dans: {output_dir}")
            print_delimiter()

        if args.functions:
            functions = with_spinner(lambda: get_functions(pe), "Collecte des fonctions importées...")
            display_functions(functions)
            print_delimiter()
            display_dll_summary(functions)
            print_delimiter()

        if args.sections:
            print("Sections du PE:")
            for section in pe.sections:
                print(f"  {section.Name.decode().strip(chr(0))}: Taille Raw={section.SizeOfRawData} bytes, Virtuelle={section.Misc_VirtualSize} bytes")
            print_delimiter()

        if args.strings:
            with open(pe_file, 'rb') as f:
                data = f.read()
            strings = with_spinner(lambda: extract_strings(data, 5), "Extraction des chaines de caractères...")
            filtered = with_spinner(lambda: filter_patterns(strings), "Filtrage des patterns intéressants...")
            print("Chaines de caractères extraites filtrées :")
            for k, v in filtered.items():
                print(f"  {k}:")
                for item in v:
                    print(f"    {item}")
            print_delimiter()

        if args.hash:
            hashes = with_spinner(lambda: get_hashes(pe_file), "Calcul des hashes...")
            print("Hashes du fichier:")
            for k, v in hashes.items():
                print(f"  {k.upper()}: {v}")
            print_delimiter()

    # ---- Analyse générale ----
    for gen_file in general_files:
        print(f"\n🔹 Analyse générale : {gen_file}")

        if args.hash:
            hashes = with_spinner(lambda: get_hashes(gen_file), "Calcul des hashes généraux...")
            print("Hashes :")
            for k, v in hashes.items():
                print(f"  {k.upper()}: {v}")
            print_delimiter()

        if args.entropy:
            with open(gen_file, "rb") as f:
                data = f.read()
            entropy = with_spinner(lambda: calculate_entropy(data), "Calcul de l'entropie...")
            print(f"Entropie globale du fichier: {entropy:.2f}")
            if entropy > 7.0:
                print("Le fichier semble packé (entropie élevée).")
            else:
                print("Le fichier ne semble pas packé (entropie normale).")

        if args.strings:
            with open(gen_file, 'rb') as f:
                data = f.read()
            strings = with_spinner(lambda: extract_strings(data, 5), "Extraction des strings générales...")
            filtered = with_spinner(lambda: filter_patterns(strings), "Filtrage des patterns générales...")
            for k, v in filtered.items():
                print(f"{k}:")
                for item in v:
                    print(item)
            print_delimiter()

    # ---- DIE ----
    if args.die:
        output = with_spinner(lambda: run_die(input_path), "Exécution de DIE...")
        print(output)
        print_delimiter()

    if args.diegui:
        msg = with_spinner(lambda: run_die_gui(input_path), "Ouverture de DIE en mode graphique...")
        print(msg)
        print_delimiter()

    # ---- YARA ----
    if args.yara:
        rules_dirs = [
            os.path.join(BASE_DIR, "yara_rules", "signature-base", "yara"),
            os.path.join(BASE_DIR, "yara_rules", "custom"),
            os.path.join(BASE_DIR, "yara_rules", "rules")
        ]
        output = with_spinner(lambda: scan_with_yara(input_path, rules_dirs),
                              "Analyse YARA en cours...")
        print("YARA Analyse terminée : ")
        print(output)
        print_delimiter()

    
    shutil.rmtree(tmp_dir)

if __name__ == "__main__":
    main()