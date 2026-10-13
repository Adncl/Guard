import os
import json
import argparse
from collections import defaultdict

def process_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading {file_path}: {e}")
            return

    if not isinstance(data, dict) or "functions" not in data:
        print(f"[!] Unexpected JSON structure in {file_path}")
        return


    functions = data["functions"]

    # Skip processing if empty or null
    if not functions:
        return

    name_to_entries = defaultdict(list)
    for entry in functions:
        name = entry.get("name")
        if name:
            name_to_entries[name].append(entry)

    new_functions = []
    for name, entries in name_to_entries.items():
        if len(entries) == 1:
            new_functions.append(entries[0])
        else:
            # Multiple entries with same name, keep those with non-null control_flow
            non_null = [e for e in entries if e.get("control_flow") is not None]
            if non_null:
                new_functions.extend(non_null)
            else:
                new_functions.extend(entries)  # All are null, keep all to prevent accidental deletion

    # Write back if count changed
    if len(new_functions) != len(functions):
        print(f"[+] Updating {file_path}")
        data["functions"] = new_functions
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def walk_and_process(root_dir):
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.startswith('.cf') and fname.endswith('.json'):
                full_path = os.path.join(dirpath, fname)
                process_json_file(full_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deduplicate functions with null control_flow in .cf*.json files.")
    parser.add_argument("path", help="Root path to recursively search for files")
    args = parser.parse_args()
    walk_and_process(args.path)
