#!/usr/bin/env python3
"""Make SukiSU's SELinux-hide hook behave like stock selinuxfs.

DuckDetector 2026.11.25 flagged two implementation fingerprints:
  A. same-FD: the hook returned -EINVAL before the transaction was armed, so a
     second write on the same fd succeeded; stock always burns the fd first.
  B. /access tail: hidden-type tokens in bytes the stock parser ignores (past
     the first NUL, or in a 4th field after the class) still reached the
     matcher, so ":ksu:" returned EINVAL while ":inv:" returned a decision.

Three surgical edits, no behaviour change for legitimate requests:
  1. selinux_hide.h        : NUL-bound the matcher + add an /access field view.
  2. selinux_hide.c        : consume the transaction before reporting EINVAL.
  3. selinux_hide_arm64.c  : same /access field view on the primary hook.

Usage:
  python3 selinux_hook_stock_fidelity.py --src <SukiSU checkout>
Exit code is non-zero when an anchor is missing, so CI fails loudly instead of
quietly shipping an unpatched kernel.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# ---------------------------------------------------------------- edit 1 ----
HDR_FUNC = "static __always_inline bool ksu_should_destroy_context(char *str, size_t limit, const bool types_only)"

HDR_HELPER = """/*
 * /access is parsed by sscanf(\"%s %s %u\"): only the source and target fields
 * carry contexts, the class is numeric and everything behind it is discarded
 * by the stock parser. Clamp the scanner to the end of the target field so an
 * extra field (or a tail glued onto the class) cannot smuggle a hidden-type
 * token into the matcher.
 */
static __always_inline size_t ksu_selinux_access_view_len(const char *str, size_t limit)
{
\tsize_t i, seps = 0;

\tif (!str)
\t\treturn 0;
\tfor (i = 0; i < limit; i++) {
\t\tif (str[i] == ' ' || str[i] == '\\t' || str[i] == '\\n') {
\t\t\tif (++seps == 2)
\t\t\t\treturn i;
\t\t}
\t}
\treturn limit;
}

"""

HDR_CLAMP_ANCHOR = """static __always_inline bool ksu_should_destroy_context(char *str, size_t limit, const bool types_only)
{
\tif (!str)
\t\treturn false;
"""

HDR_CLAMP = HDR_CLAMP_ANCHOR + """
\t/*
\t * Stock selinuxfs parses with sscanf(\"%s %s %s\"): everything after the
\t * first NUL is dead. Scanning the raw length let a NUL-separated tail
\t * (\"valid ...\\\\0:ksu:\") reach the matcher while the stock parser ignored
\t * it, which is a clean implementation fingerprint. Clamp to the string
\t * the parser would actually see; buffers without a NUL keep their length.
\t */
\tlimit = strnlen(str, limit);
"""

HDR_MARK_HELPER = "ksu_selinux_access_view_len(const char *str, size_t limit)"
HDR_MARK_CLAMP = "limit = strnlen(str, limit);"

# ---------------------------------------------------------------- edit 2 ----
SRC_BODY_ANCHOR = """\tkbuf[len] = '\\0';
\tif (ksu_should_destroy_context(kbuf, len, false)) {
\t\tpr_info_ratelimited("selinux_hide: selinux_transaction_write: destroy: %s \\n", kbuf);
\t\t// buf = (const char __user *)current->mm->start_stack;
\t\tdo_useless_alloc(len);
\t\treturn -EINVAL;
\t}
"""

SRC_BODY = """\tkbuf[len] = '\\0';
\t/*
\t * /access only carries contexts in the first two fields; /context is a
\t * single string. Give the matcher the same view the stock parser uses.
\t */
\tsize_t view = (ino == SEL_ACCESS)
\t\t? ksu_selinux_access_view_len(kbuf, len) : len;
\tif (ksu_should_destroy_context(kbuf, view, false)) {
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

SRC_MARK_BODY = "ssize_t tx = selinux_transaction_write_fn(file, buf, size, pos);"

# ---------------------------------------------------------------- edit 3 ----
ARM_ANCHOR = "\tif (ino == SEL_ACCESS && ksu_should_destroy_context(data, size, false)) {"
ARM_PATCHED = """\tif (ino == SEL_ACCESS &&
\t    ksu_should_destroy_context(data, ksu_selinux_access_view_len(data, size), false)) {"""
ARM_MARK = "ksu_selinux_access_view_len(data, size)"


def patch_header(text: str) -> tuple[str, list[str]]:
    notes = []
    if HDR_MARK_HELPER not in text:
        if HDR_FUNC not in text:
            raise SystemExit("ERROR: selinux_hide.h helper anchor not found")
        text = text.replace(HDR_FUNC, HDR_HELPER + HDR_FUNC, 1)
        notes.append("helper added")
    if HDR_MARK_CLAMP not in text:
        if HDR_CLAMP_ANCHOR not in text:
            raise SystemExit("ERROR: selinux_hide.h clamp anchor not found")
        text = text.replace(HDR_CLAMP_ANCHOR, HDR_CLAMP, 1)
        notes.append("NUL-bounded matcher")
    return text, notes or ["already patched"]


def patch_source(text: str) -> tuple[str, list[str]]:
    notes = []
    if SRC_MARK_BODY not in text:
        if SRC_BODY_ANCHOR not in text:
            raise SystemExit("ERROR: selinux_hide.c body anchor not found")
        text = text.replace(SRC_BODY_ANCHOR, SRC_BODY, 1)
        notes.append("consume-then-EINVAL")
    return text, notes or ["already patched"]


def patch_arm64(text: str) -> tuple[str, list[str]]:
    if ARM_MARK in text:
        return text, ["already patched"]
    if ARM_ANCHOR not in text:
        raise SystemExit("ERROR: selinux_hide_arm64.c anchor not found")
    return text.replace(ARM_ANCHOR, ARM_PATCHED, 1), ["/access field view"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="SukiSU checkout root")
    ap.add_argument("--check", action="store_true", help="verify anchors only")
    a = ap.parse_args()

    root = pathlib.Path(a.src) / "kernel" / "feature"
    jobs = {
        "selinux_hide.h": patch_header,
        "selinux_hide.c": patch_source,
        "selinux_hide_arm64.c": patch_arm64,
    }
    for name, fn in jobs.items():
        path = root / name
        if not path.is_file():
            print(f"ERROR: missing {path}")
            return 1
        original = path.read_text(encoding="utf-8", newline="")
        new, notes = fn(original)
        print(f"{name}: {', '.join(notes)}")
        if not a.check and new != original:
            # newline="" keeps the checkout's LF endings; text mode on Windows
            # would rewrite the whole file as CRLF and bloat the diff.
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
