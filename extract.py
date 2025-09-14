import os
import yara

def ensure_yara_is_correct():
    # Prevent importing local yara.py
    if not hasattr(yara, "compile"):
        raise RuntimeError(
            f"Imported wrong 'yara' module from {getattr(yara,'__file__',None)}. "
            "Remove local yara.py / uninstall 'yara' package, and install 'yara-python'."
        )

def load_yara_rules(yara_files):
    """Load YARA rules from provided files."""
    rules = []
    for yf in yara_files:
        try:
            rule = yara.compile(filepath=yf)
            rules.append(rule)
        except Exception as e:
            print(f"Error compiling Yara file {yf}: {e}")
    return rules

def get_line_number(file_path, offset):
    """Convert byte offset to 1-based line number."""
    with open(file_path, 'rb') as f:
        content = f.read(max(0, offset) + 1)
        return content.count(b'\n') + 1

def extract_context(file_path, line_number, context_lines=100):
    """Extract +/- context_lines around a 1-based line_number."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        total = len(lines)
        start = max(0, line_number - context_lines - 1)
        end = min(total, line_number + context_lines)
        return lines[start:end], start + 1
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return [], 0

def get_folder_name(file_path):
    """Extract first folder name after the known prefixes."""
    if '/data/phpmalware/phpmalwarefour/' in file_path:
        parts = file_path.split('/data/phpmalware/phpmalwarefour/')[1].split('/')
        return parts[0]
    if '/data/phpmalware/' in file_path:
        parts = file_path.split('/data/phpmalware/')[1].split('/')
        return parts[0]
    print(f"Invalid path format: {file_path}")
    return None

def iter_string_matches(match):
    """
    Compatible iteration for matches:
    - Older versions: match.strings is [ (offset, identifier, data), ... ]
    - Newer versions: match.strings is [ yara.StringMatch, ... ],
      where each StringMatch has .identifier and .instances (list);
      each instance may have .offset and .matched_data/.data/.string.
    Uniform output: (identifier, offset, data_bytes)
    """
    for sm in match.strings:
        # Old structure: tuple
        if isinstance(sm, tuple) and len(sm) >= 3:
            # Old format is typically (offset, identifier, data)
            offset, identifier, data = sm[0], sm[1], sm[2]
            yield (identifier, int(offset), data if isinstance(data, (bytes, bytearray, str)) else None)
            continue

        # New structure: object
        ident = getattr(sm, 'identifier', None)
        instances = getattr(sm, 'instances', None) or getattr(sm, 'matches', None) or []

        # If instances is not a list, try to convert to single-element list
        if not isinstance(instances, list):
            instances = [instances]

        for inst in instances:
            # Field names may vary between versions, try to be compatible
            offset = getattr(inst, 'offset', None)
            data = (
                getattr(inst, 'matched_data', None)
                or getattr(inst, 'data', None)
                or getattr(inst, 'string', None)
            )
            if offset is None:
                # Some strange versions may put offset directly on sm
                offset = getattr(sm, 'offset', None)
            if offset is None:
                # Skip this one if we still can't get offset
                continue
            try:
                yield (ident, int(offset), data)
            except Exception:
                # Defensive fallback
                continue

def process_file(file_path, yara_rules, context_lines=100):
    """Scan file, extract contexts for each match, and write to output."""
    try:
        folder = get_folder_name(file_path)
        if not folder:
            return

        os.makedirs(folder, exist_ok=True)
        base_name = os.path.basename(file_path).replace('.php', '_extracted.php')
        output_file = os.path.join(folder, base_name)

        matches_found = False
        output_content = []

        for rule in yara_rules:
            try:
                matches = rule.match(file_path)
            except Exception as e:
                print(f"Error matching {file_path} with rule: {e}")
                continue

            for m in matches:
                rule_name = getattr(m, 'rule', 'UNKNOWN_RULE')
                had_any = False

                for ident, offset, data in iter_string_matches(m):
                    matches_found = True
                    had_any = True

                    # Calculate line number and extract context
                    line_no = get_line_number(file_path, offset)
                    ctx_lines, start_ln = extract_context(file_path, line_no, context_lines=context_lines)
                    if not ctx_lines:
                        continue

                    header = (
                        f"// Match: Rule={rule_name}, Identifier={ident}, "
                        f"Line={line_no}, Offset={offset}, File={file_path}\n"
                    )
                    output_content.append(header)
                    output_content.extend(ctx_lines)
                    output_content.append("\n// --- End of Match ---\n\n")

                # If a rule has matches but no instances could be parsed, give a hint for troubleshooting
                if getattr(m, 'strings', None) and not had_any:
                    output_content.append(
                        f"// Match: Rule={rule_name} had strings but none could be parsed (API variant?)\n\n"
                    )

        if matches_found and output_content:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.writelines(output_content)
            print(f"Processed {file_path}, output written to {output_file}")
        else:
            print(f"No matches found in {file_path}")

    except Exception as e:
        print(f"Error processing {file_path}: {e}")

def main():
    ensure_yara_is_correct()

    # Configuration
    input_file = "large_php_files.txt"
    yara_files = ["php_malware_dna_high.yara", "php_malware_dna.yara"]

    # Load rules
    yara_rules = load_yara_rules(yara_files)
    if not yara_rules:
        print("No valid Yara rules loaded. Exiting.")
        return

    # Read list of PHP files to process (extracting paths from your large_php_files.txt text)
    try:
        php_files = []
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith("Large file found: "):
                    path = line.split("Large file found: ", 1)[1].strip()
                    if path:
                        php_files.append(path)
    except Exception as e:
        print(f"Error reading {input_file}: {e}")
        return

    # Process each file
    for fp in php_files:
        if os.path.exists(fp):
            process_file(fp, yara_rules, context_lines=100)
        else:
            print(f"File not found: {fp}")

if __name__ == "__main__":
    main()
