import argparse
import hashlib
import json
import re
from pathlib import Path


CLAUSE_HEADING_PATTERN = re.compile(
    r"""
    ^\s*
    (?:
        (?:clause|section|article)\s+
        (?P<label>[A-Za-z]?\d+(?:\.\d+)*|[IVXLCDM]+|[A-Z])
        [).:\-]?\s+
      |
        (?P<number>\d+(?:\.\d+)*)
        [).]\s+
    )
    (?P<title>[^\n]{3,120})
    \s*$
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_text_from_pdf(path):
    errors = []

    try:
        import pdfplumber

        with pdfplumber.open(path) as pdf:
            pages = [page.extract_text() or "" for page in pdf.pages]
        return "\n\n".join(pages)
    except ImportError:
        errors.append("pdfplumber is not installed")
    except Exception as exc:
        errors.append(f"pdfplumber failed: {exc}")

    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(pages)
    except ImportError:
        errors.append("PyPDF2 is not installed")
    except Exception as exc:
        errors.append(f"PyPDF2 failed: {exc}")

    raise RuntimeError(
        "Could not extract PDF text. Install pdfplumber or PyPDF2, then try again. "
        f"Details: {'; '.join(errors)}"
    )


def extract_text(path):
    if path.suffix.lower() == ".pdf":
        return extract_text_from_pdf(path)

    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        print("[Warning] File is not valid UTF-8. Falling back to Latin-1 encoding, which may alter hash outcomes if byte representations change.")
        return path.read_text(encoding="latin-1")


def normalize_clause_text(text):
    return re.sub(r"\s+", " ", text).strip()


def slugify(value):
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    slug_parts = [part for part in slug.split("_") if part]
    return "_".join(slug_parts[:8]) or "untitled"


def split_into_clauses(text):
    normalized_text = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    matches = list(CLAUSE_HEADING_PATTERN.finditer(normalized_text))

    if matches:
        clauses = []
        for index, match in enumerate(matches):
            start = match.start()
            end = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(normalized_text)
            )
            title = match.group("title").strip(" .:-")
            clause_text = normalize_clause_text(normalized_text[start:end])

            if clause_text:
                clause_id = f"clause_{index + 1}_{slugify(title)}"
                clauses.append((clause_id, clause_text))

        return clauses

    paragraphs = [
        normalize_clause_text(paragraph)
        for paragraph in re.split(r"\n\s*\n+", normalized_text)
        if normalize_clause_text(paragraph)
    ]
    return [
        (f"clause_{index}", paragraph)
        for index, paragraph in enumerate(paragraphs, start=1)
    ]


def calculate_root_hash(manifest_dict):
    clause_keys = sorted([k for k in manifest_dict.keys() if not k.startswith("__")])
    combined = "".join(f"{k}:{manifest_dict[k]}" for k in clause_keys)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def build_clause_manifest(contract_path):
    contract_text = extract_text(contract_path)
    clauses = split_into_clauses(contract_text)

    if not clauses:
        raise ValueError("No clause text found in the document.")

    return {clause_id: sha256_text(clause_text) for clause_id, clause_text in clauses}


def save_clause_manifest(contract_path, manifest_path):
    manifest = build_clause_manifest(contract_path)
    root_hash = calculate_root_hash(manifest)
    manifest["__root_hash__"] = root_hash
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(manifest) - 1} clause hashes to {manifest_path} (Root Hash: {root_hash})")
    return 0


def print_local_storage_warning(file_path, hash_path):
    if hash_path.parent.resolve() == file_path.parent.resolve():
        print(
            "SECURITY WARNING: Hash file is stored on the same local filesystem directory as the contract. "
            "An attacker who can modify the contract can also modify the stored hash. "
            "For production-grade security, store hashes off-trust-domain (e.g. using the Fabric blockchain ledger)."
        )


def save_hash(file_path, hash_path):
    print_local_storage_warning(file_path, hash_path)
    file_hash = sha256_file(file_path)
    hash_path.write_text(file_hash + "\n", encoding="utf-8")
    print(f"Saved SHA-256 hash to {hash_path}")
    print(file_hash)


def verify_hash(file_path, hash_path):
    print_local_storage_warning(file_path, hash_path)
    current_hash = sha256_file(file_path)
    saved_hash = hash_path.read_text(encoding="utf-8").strip()

    if current_hash == saved_hash:
        print("OK: file has not been tampered with.")
        return 0

    print("WARNING: file may have been tampered with.")
    print(f"Saved:   {saved_hash}")
    print(f"Current: {current_hash}")
    return 1


def parse_args():
    parser = argparse.ArgumentParser(
        description="Save/verify file hashes and build clause-level hash manifests."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    save_parser = subparsers.add_parser("save", help="Generate and save a hash.")
    save_parser.add_argument("file", type=Path, help="Text file to hash.")
    save_parser.add_argument(
        "--hash-file",
        type=Path,
        help="Where to store the hash. Defaults to '<file>.sha256'.",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a file against a saved hash."
    )
    verify_parser.add_argument("file", type=Path, help="Text file to verify.")
    verify_parser.add_argument(
        "--hash-file",
        type=Path,
        help="Hash file to read. Defaults to '<file>.sha256'.",
    )

    manifest_parser = subparsers.add_parser(
        "manifest", help="Generate a clause-level hash manifest."
    )
    manifest_parser.add_argument(
        "file", type=Path, help="PDF or text contract to process."
    )
    manifest_parser.add_argument(
        "-o",
        "--manifest-file",
        type=Path,
        default=Path("manifest.json"),
        help="Where to store the manifest. Defaults to 'manifest.json'.",
    )

    return parser.parse_args()


def resolve_paths(args):
    file_path = args.file
    hash_path = args.hash_file or file_path.with_name(file_path.name + ".sha256")

    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path, hash_path


def main():
    args = parse_args()

    if args.command == "manifest":
        if not args.file.is_file():
            raise FileNotFoundError(f"File not found: {args.file}")

        return save_clause_manifest(args.file, args.manifest_file)

    file_path, hash_path = resolve_paths(args)

    if args.command == "save":
        save_hash(file_path, hash_path)
        return 0

    if not hash_path.is_file():
        raise FileNotFoundError(f"Hash file not found: {hash_path}")

    return verify_hash(file_path, hash_path)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
