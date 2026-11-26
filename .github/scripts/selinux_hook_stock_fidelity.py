#!/usr/bin/env python3
"""Make SukiSU's SELinux-hide hook behave like stock selinuxfs.

Problem (DuckDetector 2026.11.25, "xxksu SELinuxFS transaction-state anomaly"):
  the hook returned -EINVAL *before* the transaction was armed, and it matched
  hidden-type tokens over the raw write size instead of the NUL-terminated
  fields that sscanf() would consume. Both are observable with placebo probes.

Fix (two surgical edits, no behaviour change for legitimate requests):
  1. selinux_hide.h  : bound the matcher to the first NUL (stock parser view).
  2. selinux_hide.c  : on a hidden hit, run the real transaction first so the
                       fd is consumed exactly like stock's parse-failure path,
                       then report EINVAL.

Usage:
  python3 selinux_hook_stock_fidelity.py --src <SukiSU checkout>
  python3 selinux_hook_stock_fidelity.py --file selinux_hide.c --file selinux_hide.h
Exit code is non-zero when an anchor is missing, so CI fails loudly instead of
silently shipping an unhooked kernel.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

OOM = object()

# ---------------------------------------------------------------- edit 1 ----
HDR_ANCHOR = """static __always_inline bool ksu_should_destroy_context(char *str, size_t limit, const bool types_only)
{
\tif (!str)
\t\treturn false;
"""

HDR_PATCHED = HDR_ANCHOR + """
\t/*
\t * Stock selinuxfs parses with sscanf(\"%s %s %s\"): everything after the
\t * first NUL is dead. Scanning the raw length let a NUL-separated tail
\t * (\"valid ...\\\\0:ksu:\") reach the matcher while the stock parser ignored
\t * it, which is a clean implementation fingerprint. Clamp to the string
\t * the parser would actually see; buffers without a NUL keep their length.
\t */
\tlimit = strnlen(str, limit);
"""

HDR_MARK = "limit = strnlen(str, limit);"

# ---------------------------------------------------------------- edit 2 ----
SRC_ANCHOR = """\tif (ksu_should_destroy_context(kbuf, len, false)) {
\t\tpr_info_ratelimited("selinux_hide: selinux_transaction_write: destroy: %s \\n", kbuf);
\t\t// buf = (const char __user *)current->mm->start_stack;
\t\tdo_useless_alloc(len);
\t\treturn -EINVAL;
\t}
"""

SRC_PATCHED = """\tif (ksu_should_destroy_context(kbuf, len, false)) {
\t\tpr_info_ratelimited("selinux_hide: selinux_transaction_write: destroy: %s \\n", kbuf);
\t\t/*
\t\t * Stock always runs simple_transaction_get() before it parses, so a
\t\t * rejected request still burns the fd (one write per open) and the next
\t\t * write reports -EBUSY. Returning here first left the fd reusable and a
\t\t * same-FD probe saw EINVAL -> success, which stock never does.
\t\t *
\t\t * Delegate to the real write so the transaction state matches stock
\t\t * byte for byte, then blank the response: stock's parse-failure path
\t\t * leaves ar->size == 0, so a read() after the error returns nothing.
\t\t */
\t\tssize_t tx = selinux_transaction_write_fn(file, buf, size, pos);
\t\tif (tx < 0)
\t\t\treturn tx; /* -EBUSY when the fd was already used, -EFAULT, ... */

\t\tif (file->private_data) {
\t\t\tstruct simple_transaction_argresp *ar = file->private_data;
\t\t\tar->size = 0;
\t\t}
\t\treturn -EINVAL;
\t}
"""

SRC_MARK = "selinux_transaction_write_fn(file, buf, size, pos);\n\t\tif (tx < 0)"

DROP_NOISE_ANCHOR = """\tif (ksu_should_destroy_context(kbuf, len, false)) {
\t\tpr_info_ratelimited("selinux_hide: selinux_transaction_write: destroy: %s \\n", kbuf);
\t\t// buf = (const char __user *)current->mm->start_stack;
\t\tdo_useless_alloc(len);
\t\treturn -EINVAL;
"""


def patch_header(text: str) -> tuple[str, str]:
    if HDR_MARK in text:
        return text, "already patched"
    if HDR_ANCHOR not in text:
        raise SystemExit("ERROR: selinux_hide.h anchor not found -- upstream layout changed")
    return text.replace(HDR_ANCHOR, HDR_PATCHED, 1), "patched (NUL-bounded matcher)"


def patch_source(text: str) -> tuple[str, str]:
    if SRC_MARK in text:
        return text, "already patched"
    if SRC_ANCHOR not in text:
        raise SystemExit("ERROR: selinux_hide.c anchor not found -- upstream layout changed")
    return text.replace(SRC_ANCHOR, SRC_PATCHED, 1), "patched (consume-then-EINVAL)"


def resolve(args) -> list[pathlib.Path]:
    if args.file:
        return [pathlib.Path(p) for p in args.file]
    root = pathlib.Path(args.src) / "kernel" / "feature"
    return [root / "selinux_hide.c", root / "selinux_hide.h"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", help="SukiSU checkout root")
    ap.add_argument("--file", action="append", help="explicit source file (repeatable)")
    ap.add_argument("--check", action="store_true", help="only verify anchors; do not write")
    a = ap.parse_args()
    if not a.src and not a.file:
        ap.error("give --src or --file")

    files = resolve(a)
    rc = 0
    for path in files:
        if not path.is_file():
            print(f"ERROR: missing {path}")
            return 1
        original = path.read_text(encoding="utf-8", newline="")
        if path.name == "selinux_hide.h":
            new, note = patch_header(original)
        elif path.name == "selinux_hide.c":
            new, note = patch_source(original)
        else:
            continue
        print(f"{path.name}: {note}")
        if not a.check and new != original:
            # newline="" keeps the checkout's LF endings; text mode on Windows
            # would rewrite the whole file as CRLF and bloat the diff.
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
    return rc


if __name__ == "__main__":
    sys.exit(main())
