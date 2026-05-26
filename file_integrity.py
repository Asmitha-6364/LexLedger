import argparse
import hashlib
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def save_hash(file_path, hash_path):
    file_hash = sha256_file(file_path)
    hash_path.write_text(file_hash + "\n", encoding="utf-8")
    print(f"Saved SHA-256 hash to {hash_path}")
    print(file_hash)


def verify_hash(file_path, hash_path):
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
        description="Save and verify a file's SHA-256 hash."
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

    return parser.parse_args()


def resolve_paths(args):
    file_path = args.file
    hash_path = args.hash_file or file_path.with_name(file_path.name + ".sha256")

    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path, hash_path


def main():
    args = parse_args()
    file_path, hash_path = resolve_paths(args)

    if args.command == "save":
        save_hash(file_path, hash_path)
        return 0

    if not hash_path.is_file():
        raise FileNotFoundError(f"Hash file not found: {hash_path}")

    return verify_hash(file_path, hash_path)


if __name__ == "__main__":
    raise SystemExit(main())
