# pdf-unlock

**Remove the "permission password" prompt from PDFs.** No password cracking — it only
strips owner-password *restrictions* (edit / annotate / copy / print blocks) from files
that already open without a password.

[中文说明见下方](#中文说明) · MIT licensed · pure Python

---

## The problem

You open a PDF, it displays fine, but the moment you try to edit, annotate, fill a form
or merge pages, the viewer demands a password:

> 文件 “xxx.pdf” 被保护，请输入权限密码

This is **owner-password protection**. The document has *no* open password — anyone can
read it — but the file carries a permission flag (`/P` in the PDF spec) that tells
software to block those actions. Many exam papers, textbooks, invoices and government
forms ship this way.

`pdf-unlock` removes the encryption layer entirely and writes a clean, unrestricted copy.
Your original file is never touched.

## What it does and does not do

| | |
|---|---|
| ✅ Removes owner-password (permission) restrictions | ❌ Does **not** crack open passwords |
| ✅ Handles RC4-40 / RC4-128 / AES-128 / AES-256 | ❌ Does **not** bypass DRM or decrypt paywalled content |
| ✅ Preserves text, images, outlines, form fields, links, metadata, page labels | ❌ Does **not** rasterize — text stays selectable and searchable |

If a file genuinely requires a password to *open*, the tool stops and says so. That is a
deliberate limit: recovering a lost open password is a different problem, and this tool
does not attempt it.

## Install

```bash
pip install "pypdf[crypto]"
```

Two packages, both required:

- **pypdf** — parsing and rebuilding the document
- **cryptography** — decrypting AES. Without it, AES-128/256 files fail, and AES-256
  is what Acrobat and WPS emit by default, so this is **not** optional.

Or just grab the single file — it has no imports beyond those two packages:

```bash
curl -O https://raw.githubusercontent.com/l0s3r-Q/pdf-unlock/main/pdf_unlock.py
```

If `cryptography` is missing, the tool says so and prints the install command instead
of crashing with a traceback.

## Usage

```bash
# one file — writes book_unlocked.pdf next to it
python pdf_unlock.py book.pdf

# a whole folder into a separate output directory
python pdf_unlock.py ./inbox/ --outdir ./unlocked/

# see what is blocked without writing anything
python pdf_unlock.py book.pdf --dry-run

# machine-readable output for scripting
python pdf_unlock.py ./*.pdf --json
```

Sample output:

```
  ok    2026年6月英语四级真题(第1套).pdf
        was blocked: modify, annotate, fill_forms, assemble
        -> ./unlocked/2026年6月英语四级真题(第1套).pdf
```

### Options

| Flag | Meaning |
|---|---|
| `-o, --outdir DIR` | Write results into `DIR` |
| `--overwrite` | Allow replacing an existing output file |
| `--dry-run` | Inspect and report only, write nothing |
| `--json` | Emit JSON instead of human-readable text |

Exit code is `0` on success, `1` if any file could not be processed (e.g. it needs an
open password), `2` if no PDFs were found — so it is safe to use in shell pipelines.

## As a library

```python
from pathlib import Path
from pdf_unlock import unlock_pdf

result = unlock_pdf(Path("locked.pdf"), Path("clean.pdf"))
if result.status == "unlocked":
    print("was blocked:", result.permissions_before.denied)
elif result.status == "needs_password":
    print("this file needs an open password; refusing")
```

`unlock_pdf` never modifies its input and never writes a file it cannot fully open.

## How it works

1. Parse the file and look for an `/Encrypt` dictionary.
2. Try the **empty user password**. In owner-password-only files this succeeds — the
   content stream is decryptable, only the permission flags say "don't edit".
3. Read the original `/P` value from the trailer and decode it into human terms, so you
   can see exactly what was blocked.
4. Rebuild the document with a fresh writer and save it **without** an `/Encrypt`
   dictionary. The output is a plain, unencrypted PDF.
5. Re-attach `/Metadata` and `/PageLabels`, which the rebuild step would otherwise drop.

Step 5 matters more than it looks: naively re-saving a PDF silently loses its title,
author and custom page numbering. A test guards against that regression.

## Safety notes

- **The source file is opened read-only and never written.** Output goes to a new path.
- Existing output files are **not** overwritten unless you pass `--overwrite`.
- Files that need an open password produce no output at all.
- Validated by round-tripping text and structure, then editing the result with an
  independent PDF library to prove the restrictions are really gone.

## Tested against

`RC4-40`, `RC4-128`, `AES-128`, `AES-256` (Standard V5 R6, the format Acrobat and WPS
produce by default), plus corrupt files, plain unencrypted PDFs, and files with real
open passwords.

```bash
pip install "pypdf[crypto]" pytest pymupdf
python -m pytest tests/ -v
```

The test suite generates all fixtures at runtime, so no sample PDFs are committed.

## Legal

Use this only on documents you have the right to modify — your own files, or files whose
licence permits it. Removing restrictions may be contrary to the terms a publisher
intended, even though the file itself is not password-protected. In many jurisdictions
(including under EU law and US fair-use doctrine) you may have a right to extract text
or format-shift content you lawfully acquired, but that is your call to make, not this
tool's.

---

## 中文说明

**一行命令去掉 PDF 的「权限密码」弹窗。**

这个工具**不破解密码**。它只处理一种情况：文件能正常打开阅读，但一编辑 / 批注 /
填表 / 合并就弹出「请输入权限密码」。这类文件其实**没有打开密码**，只是带了一个
"禁止编辑" 的权限标记位。工具把这层限制彻底移除，导出干净的无加密副本。

### 它会 / 不会做什么

| | |
|---|---|
| ✅ 移除所有者密码（权限）限制 | ❌ **不**破解打开密码 |
| ✅ 支持 RC4-40 / RC4-128 / AES-128 / AES-256 | ❌ 不绕过 DRM、不解密付费内容 |
| ✅ 保留文字、图片、书签、表单域、链接、元数据、页码标签 | ❌ 不做光栅化，文字依然可选中可搜索 |

如果文件真的需要密码才能**打开**，工具会直接停下并提示——这是刻意的边界。

### 安装与使用

```bash
pip install "pypdf[crypto]"

# 单文件：在同目录生成 xxx_unlocked.pdf
python pdf_unlock.py 真题.pdf

# 整个文件夹输出到指定目录
python pdf_unlock.py ./待处理/ --outdir ./已解锁/

# 只查看被限制了哪些权限，不写文件
python pdf_unlock.py 真题.pdf --dry-run
```

输出示例：

```
  ok    2026年6月英语四级真题(第1套).pdf
        was blocked: modify, annotate, fill_forms, assemble
        -> ./已解锁/2026年6月英语四级真题(第1套).pdf
```

### 原理

这类文件只有**所有者密码**、没有**用户密码**。因此用空密码就能解开内容加密，剩下
的只是 `/P` 权限标志位在阻止软件编辑。工具读取 `/P` 并解码成人类可读的权限列表，
然后用一个不带 `/Encrypt` 字典的新文档重写，得到真正的无加密 PDF。

### 注意

- 原文件**只读打开，永不修改**，结果写入新文件。
- 不覆盖已有文件（除非显式 `--overwrite`）。
- 请仅对自己有权修改的文档使用本工具。

## License

MIT — see [LICENSE](LICENSE).
