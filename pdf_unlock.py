#!/usr/bin/env python3
"""
pdf-unlock — remove permission restrictions from PDFs you legitimately own.

This tool does NOT crack passwords. It only handles PDFs that open without
a password but block editing / printing / copying through an *owner password*
(the "permission password" prompt you see in Acrobat, WPS, Edge, etc.).

If a file requires a real password to open, this tool refuses and tells you.

Licence: MIT. Requires: pypdf (BSD).
"""

from __future__ import annotations

import argparse
import io
import shutil
import sys
from pathlib import Path
from typing import Iterable, NamedTuple

try:
    from pypdf import PasswordType, PdfReader, PdfWriter
    from pypdf.errors import DependencyError
    from pypdf.generic import NameObject
except ImportError:  # pragma: no cover
    sys.exit("error: pypdf is not installed.  Try:  pip install \"pypdf[crypto]\"")

MISSING_CRYPTO_HINT = (
    "this file uses AES encryption, which needs the 'cryptography' package. "
    'Fix with:  pip install "pypdf[crypto]"  or  pip install cryptography'
)

__version__ = "1.0.0"

# The permission bits stored in /P, as defined by the PDF spec (Table 22).
PERMISSION_FLAGS = [
    (1 << 2, "print", "Print the document"),
    (1 << 3, "modify", "Modify contents (edit text, images)"),
    (1 << 4, "copy", "Copy / extract text and graphics"),
    (1 << 5, "annotate", "Add or modify annotations and form fields"),
    (1 << 8, "fill_forms", "Fill in existing form fields"),
    (1 << 9, "extract_accessibility", "Extract for accessibility tools"),
    (1 << 10, "assemble", "Assemble the document (insert, rotate, delete pages)"),
    (1 << 11, "print_hq", "Print in high resolution"),
]


class PermissionSet(NamedTuple):
    """Decoded meaning of a /P value."""

    raw: int
    allowed: dict[str, bool]

    @property
    def denied(self) -> list[str]:
        return [k for k, ok in self.allowed.items() if not ok]

    def describe(self) -> str:
        granted = [k for k, ok in self.allowed.items() if ok]
        return ", ".join(granted) if granted else "none"


def decode_permissions(p: int) -> PermissionSet:
    """Decode a signed /P integer into human-readable permission flags.

    PDF stores /P as a signed 32-bit integer, so permission bits 1-8 appear in
    the high bits and the low two bits are always set (they are reserved and
    must be 1). We mask to 32 bits first to undo sign extension.
    """
    unsigned = p & 0xFFFFFFFF
    return PermissionSet(
        raw=p,
        allowed={name: bool(unsigned & bit) for bit, name, _ in PERMISSION_FLAGS},
    )


class UnlockResult(NamedTuple):
    source: Path
    destination: Path | None
    status: str  # "unlocked" | "not_encrypted" | "needs_password" | "error"
    message: str
    permissions_before: PermissionSet | None = None


def _copy_document_properties(reader: PdfReader, writer: PdfWriter) -> None:
    """Carry over the things PdfWriter.append() silently drops.

    pypdf's append() rebuilds the document tree, which loses /Metadata and
    /PageLabels but keeps outlines, annotations and AcroForm fields. Re-attaching
    them here is what separates a correct conversion from a lossy one.
    """
    reader_root = reader.trailer.get("/Root", {})

    page_labels = reader_root.get("/PageLabels")
    if page_labels is not None:
        writer._root_object[NameObject("/PageLabels")] = page_labels

    metadata = reader.metadata
    if metadata:
        printable = {
            str(key): str(value)
            for key, value in metadata.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        if printable:
            writer.add_metadata(printable)


def default_destination(source: Path) -> Path:
    """Where the unlocked copy goes when the caller does not say."""
    source = Path(source)
    return source.with_name(f"{source.stem}_unlocked{source.suffix}")


def read_permission_flags(reader: PdfReader) -> PermissionSet:
    """Read the /P value straight from the encryption dictionary.

    ``reader.user_access_permissions`` is not usable here: pypdf adjusts it based
    on which password unlocked the file, so it reports "everything allowed" once
    the empty user password is accepted. The raw /P in the trailer is the ground
    truth and stays constant before and after decryption.
    """
    encrypt_dict = reader.trailer.get("/Encrypt")
    if encrypt_dict is None:
        return decode_permissions(-4)  # unencrypted: no restrictions
    raw = encrypt_dict.get("/P", -4)
    return decode_permissions(int(raw))


def unlock_pdf(
    source: Path,
    destination: Path | None = None,
    *,
    password: str = "",
    overwrite: bool = False,
    dry_run: bool = False,
) -> UnlockResult:
    """Strip permission restrictions from ``source`` and write ``destination``.

    ``source`` is never modified when ``destination`` points elsewhere.
    With ``dry_run`` the file is inspected but nothing is written.
    """
    source = Path(source)
    if destination is None:
        destination = default_destination(source)
    destination = Path(destination)

    try:
        reader = PdfReader(str(source))
    except DependencyError:
        # pypdf also raises this while *parsing* an AES file, before decrypt().
        return UnlockResult(source, None, "missing_dependency", MISSING_CRYPTO_HINT)
    except Exception as exc:  # noqa: BLE001 - surface any parse failure to the user
        return UnlockResult(source, None, "error", f"cannot read file: {exc}")

    if not reader.is_encrypted:
        return UnlockResult(
            source, None, "not_encrypted", "file is not encrypted, nothing to do"
        )

    try:
        attempt = reader.decrypt(password)
    except DependencyError:
        # pypdf raises this when the file uses AES but no crypto backend is
        # installed. Give an actionable message instead of a stack trace.
        return UnlockResult(source, None, "missing_dependency", MISSING_CRYPTO_HINT)

    if attempt == PasswordType.NOT_DECRYPTED:
        # A real user password is required to open the file. We deliberately
        # stop here: this tool removes permission flags, it does not crack.
        return UnlockResult(
            source,
            None,
            "needs_password",
            "file requires an open password; this tool does not crack passwords",
        )

    permissions_before = read_permission_flags(reader)

    if dry_run:
        return UnlockResult(
            source,
            destination,
            "unlocked",
            "would remove permission restrictions (dry run)",
            permissions_before,
        )

    if destination.exists() and not overwrite:
        return UnlockResult(
            source,
            None,
            "error",
            f"destination exists: {destination} (use --overwrite)",
            permissions_before,
        )

    try:
        writer = PdfWriter()
        writer.append(reader)  # type: ignore[arg-type]
        _copy_document_properties(reader, writer)

        buffer = io.BytesIO()
        writer.write(buffer)  # unencrypted: no /Encrypt dict is emitted
        buffer.seek(0)

        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as handle:
            shutil.copyfileobj(buffer, handle)
    except DependencyError:
        return UnlockResult(
            source, None, "missing_dependency", MISSING_CRYPTO_HINT, permissions_before
        )
    except Exception as exc:  # noqa: BLE001
        return UnlockResult(
            source, None, "error", f"failed to write output: {exc}", permissions_before
        )

    return UnlockResult(
        source,
        destination,
        "unlocked",
        "permission restrictions removed",
        permissions_before,
    )


def iter_pdfs(paths: Iterable[str]) -> list[Path]:
    """Expand directories into the PDF files they contain."""
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() == ".pdf"))
        else:
            found.append(path)
    return found


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf-unlock",
        description=(
            "Remove permission restrictions (owner-password protection) from PDFs. "
            "This does not crack open passwords."
        ),
        epilog="example:  pdf-unlock book.pdf --outdir unlocked/",
    )
    parser.add_argument("files", nargs="+", help="PDF files or directories")
    parser.add_argument(
        "-o", "--outdir", metavar="DIR", help="write results to DIR (default: alongside source)"
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="allow replacing existing output files"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="inspect only, do not write anything"
    )
    parser.add_argument(
        "--json", action="store_true", help="machine-readable output"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    targets = iter_pdfs(args.files)

    if not targets:
        print("error: no PDF files found", file=sys.stderr)
        return 2

    results: list[UnlockResult] = []
    for source in targets:
        if args.outdir:
            destination = Path(args.outdir) / source.name
        else:
            destination = default_destination(source)

        result = unlock_pdf(
            source, destination, overwrite=args.overwrite, dry_run=args.dry_run
        )
        results.append(result)

        if not args.json:
            _report(result, dry_run=args.dry_run)

    if args.json:
        import json

        payload = [
            {
                "source": str(r.source),
                "destination": str(r.destination) if r.destination else None,
                "status": r.status,
                "message": r.message,
                "permissions_before": r.permissions_before.allowed
                if r.permissions_before
                else None,
            }
            for r in results
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    failures = sum(
        1 for r in results if r.status in {"error", "needs_password", "missing_dependency"}
    )
    return 1 if failures else 0


def _report(result: UnlockResult, *, dry_run: bool) -> None:
    name = result.source.name
    if result.status == "unlocked":
        before = result.permissions_before
        if before:
            blocked = ", ".join(before.denied) or "nothing"
            print(f"  ok    {name}")
            print(f"        was blocked: {blocked}")
        else:
            print(f"  ok    {name}")
        if not dry_run and result.destination:
            print(f"        -> {result.destination}")
        else:
            print("        (dry run: nothing written)")
    elif result.status == "not_encrypted":
        print(f"  skip  {name}: {result.message}")
    elif result.status == "needs_password":
        print(f"  STOP  {name}")
        print(f"        {result.message}")
    elif result.status == "missing_dependency":
        print(f"  DEPS  {name}")
        print(f"        {result.message}")
    else:
        print(f"  error {name}: {result.message}")


if __name__ == "__main__":
    raise SystemExit(main())
