"""Tests for pdf-unlock.

Fixtures are generated on the fly so the repository ships no binaries and the
suite can exercise every encryption handler without needing sample files.
"""

from __future__ import annotations

import io

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.constants import UserAccessPermissions

import pdf_unlock
from pdf_unlock import decode_permissions, unlock_pdf

ALGORITHMS = ["RC4-40", "RC4-128", "AES-128", "AES-256"]

# Print + copy allowed, but editing/annotating/assembling blocked. This mirrors
# the restriction profile most "permission password" PDFs actually ship with.
PRINT_ONLY = UserAccessPermissions.PRINT | UserAccessPermissions.EXTRACT


def make_pdf(
    path,
    *,
    user_password="",
    owner_password="owner-secret",
    algorithm="AES-256",
    permissions_flag=PRINT_ONLY,
    title="Fixture Title",
):
    """Build a small PDF, optionally encrypted, and return its path."""
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=400)
    page.extract_text()  # touch the page so pypdf registers it
    writer.add_metadata({"/Title": title, "/Author": "Test Author"})
    writer.add_outline_item("First chapter", 0)

    if owner_password is not None:
        writer.encrypt(
            user_password=user_password,
            owner_password=owner_password,
            algorithm=algorithm,
            permissions_flag=permissions_flag,
        )

    writer.write(str(path))
    return path


# --------------------------------------------------------------------------- #
# Permission decoding
# --------------------------------------------------------------------------- #


def test_decodes_printed_but_not_editable():
    # 0xFFFFFAD4: the exact value found on files that block editing.
    perms = decode_permissions(-1324)
    assert perms.allowed["print"] is True
    assert perms.allowed["copy"] is True
    assert perms.allowed["modify"] is False
    assert perms.allowed["annotate"] is False
    assert perms.allowed["fill_forms"] is False
    assert perms.allowed["assemble"] is False
    assert set(perms.denied) == {"modify", "annotate", "fill_forms", "assemble"}


def test_fully_locked_down():
    perms = decode_permissions(0xFFFFF0C0 | 0)  # no permission bits set
    assert perms.denied == [
        "print",
        "modify",
        "copy",
        "annotate",
        "fill_forms",
        "extract_accessibility",
        "assemble",
        "print_hq",
    ]


def test_fully_open():
    perms = decode_permissions(-4)  # 0xFFFFFFFC: every permission bit set
    assert perms.denied == []


def test_sign_extension_is_masked():
    """A negative /P must decode the same as its unsigned counterpart."""
    assert decode_permissions(-1324).allowed == decode_permissions(0xFFFFFAD4).allowed


# --------------------------------------------------------------------------- #
# The core promise: owner-password-only files become editable
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_unlocks_owner_only_files_for_every_handler(tmp_path, algorithm):
    source = make_pdf(tmp_path / "locked.pdf", algorithm=algorithm)
    destination = tmp_path / "out.pdf"

    result = unlock_pdf(source, destination)

    assert result.status == "unlocked", result.message
    assert destination.exists()
    # The report must name what was blocked, not just say "ok".
    assert "modify" in result.permissions_before.denied


def test_output_is_no_longer_encrypted(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"
    unlock_pdf(source, destination)

    reader = PdfReader(str(destination))
    assert reader.is_encrypted is False
    assert "/Encrypt" not in reader.trailer


def test_page_count_and_metadata_survive(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf", title="Keep Me")
    destination = tmp_path / "out.pdf"
    unlock_pdf(source, destination)

    reader = PdfReader(str(destination))
    assert len(reader.pages) == 1
    # append() drops metadata; _copy_document_properties() restores it.
    assert reader.metadata.title == "Keep Me"
    assert reader.metadata.author == "Test Author"


def test_outline_survives(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"
    unlock_pdf(source, destination)

    reader = PdfReader(str(destination))
    assert len(reader.outline) == 1


def test_output_is_editable_with_an_independent_library(tmp_path):
    """Guard against 'technically decrypted but still restricted' regressions."""
    pymupdf = pytest.importorskip("pymupdf")

    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"
    unlock_pdf(source, destination)

    doc = pymupdf.open(str(destination))
    page = doc[0]
    page.insert_text((40, 40), "edited")
    page.add_freetext_annot(pymupdf.Rect(50, 50, 200, 80), "note")
    doc.set_metadata({"title": "Edited"})
    written = tmp_path / "edited.pdf"
    doc.save(str(written))  # raises if the file is still permission-restricted
    doc.close()

    assert pymupdf.open(str(written)).metadata["title"] == "Edited"


# --------------------------------------------------------------------------- #
# The limits: real passwords are refused, never cracked
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_refuses_files_with_a_real_open_password(tmp_path, algorithm):
    source = make_pdf(
        tmp_path / "secret.pdf", user_password="letmein", algorithm=algorithm
    )
    destination = tmp_path / "out.pdf"

    result = unlock_pdf(source, destination)

    assert result.status == "needs_password"
    assert destination.exists() is False, "must not write anything we cannot open"
    assert "password" in result.message


def test_not_encrypted_files_are_left_alone(tmp_path):
    source = make_pdf(tmp_path / "plain.pdf", owner_password=None)
    destination = tmp_path / "out.pdf"

    result = unlock_pdf(source, destination)

    assert result.status == "not_encrypted"
    assert destination.exists() is False


def test_supplying_the_open_password_works(tmp_path):
    """If the user knows the password, we should still clean the file."""
    source = make_pdf(tmp_path / "secret.pdf", user_password="letmein")
    destination = tmp_path / "out.pdf"

    result = unlock_pdf(source, destination, password="letmein")

    assert result.status == "unlocked"
    assert PdfReader(str(destination)).is_encrypted is False


# --------------------------------------------------------------------------- #
# Safety and ergonomics
# --------------------------------------------------------------------------- #


def test_source_file_is_never_modified(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    original = source.read_bytes()

    unlock_pdf(source, tmp_path / "out.pdf")

    assert source.read_bytes() == original


def test_refuses_to_overwrite_without_flag(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"
    destination.write_bytes(b"precious")

    result = unlock_pdf(source, destination)

    assert result.status == "error"
    assert destination.read_bytes() == b"precious"


def test_overwrite_flag_replaces_output(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"
    destination.write_bytes(b"stale")

    result = unlock_pdf(source, destination, overwrite=True)

    assert result.status == "unlocked"
    assert destination.read_bytes() != b"stale"


def test_dry_run_writes_nothing(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    destination = tmp_path / "out.pdf"

    result = unlock_pdf(source, destination, dry_run=True)

    assert result.status == "unlocked"
    assert result.permissions_before is not None
    assert destination.exists() is False


def test_default_destination_avoids_clobbering(tmp_path):
    source = make_pdf(tmp_path / "locked.pdf")
    result = unlock_pdf(source)

    assert result.destination == tmp_path / "locked_unlocked.pdf"
    assert result.destination.exists()


def test_corrupt_file_reports_error(tmp_path):
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(b"not a pdf at all")

    result = unlock_pdf(broken, tmp_path / "out.pdf")

    assert result.status == "error"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_processes_a_directory(tmp_path, capsys):
    inputs = tmp_path / "in"
    inputs.mkdir()
    make_pdf(inputs / "a.pdf")
    make_pdf(inputs / "b.pdf")
    outdir = tmp_path / "out"

    code = pdf_unlock.main([str(inputs), "--outdir", str(outdir)])

    assert code == 0
    assert len(list(outdir.glob("*.pdf"))) == 2
    assert "ok" in capsys.readouterr().out


def test_cli_exit_code_signals_unopenable_files(tmp_path):
    make_pdf(tmp_path / "secret.pdf", user_password="letmein")
    code = pdf_unlock.main([str(tmp_path / "secret.pdf"), "--outdir", str(tmp_path)])
    assert code == 1


def test_cli_json_output_is_parseable(tmp_path, capsys):
    import json

    source = make_pdf(tmp_path / "locked.pdf")
    code = pdf_unlock.main([str(source), "--outdir", str(tmp_path / "o"), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload[0]["status"] == "unlocked"
    assert payload[0]["permissions_before"]["modify"] is False
