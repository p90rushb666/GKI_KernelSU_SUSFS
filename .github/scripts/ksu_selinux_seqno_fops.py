#!/usr/bin/env python3
"""Zero the policy generation reported by /sys/fs/selinux/access.

Patching the security_compute_av_user call site looked successful but had no
effect (LTO inlines it into sel_write_access), so the reply kept the real
generation. Instead wrap the fops write of the /access node: let stock run
untouched, then rewrite the fifth field of the reply.

Why zero: a clean phone reports 0 for status.sequence, status.policyload and the
access seqno. Anything else implies the policy was rewritten.

Three edits, all in selinux_hide.c/.h:
  A. header : KSU_SELINUX_FAKE_SEQNO 1 -> 0
  B. hide.c : wrapper + ksu_install_access_seqno_hook() (fops based)
  C. hide.c : install it once the fake status page exists

No request is intercepted, so same-FD / tail behaviour stays stock.

Usage: python3 ksu_selinux_seqno_fops.py --src <SukiSU checkout>
"""

from __future__ import annotations

import argparse
import pathlib
import sys

HDR_OLD = "#define KSU_SELINUX_FAKE_SEQNO 1"
HDR_NEW = "#define KSU_SELINUX_FAKE_SEQNO 0"

HOOK = """
static ssize_t (*ksu_access_write_fn)(struct file *file, const char __user *buf,
\t\t\t\t      size_t size, loff_t *pos) __read_mostly;

static __nocfi ssize_t ksu_access_seqno_write(struct file *file, const char __user *buf,
\t\t\t\t\t      size_t size, loff_t *pos)
{
\tssize_t ret = ksu_access_write_fn(file, buf, size, pos);

\tif (ret > 0)
\t\treturn ksu_selinux_hide_fake_access_seqno(file, ret);
\treturn ret;
}

void ksu_install_access_seqno_hook(void)
{
\tint ret;

\tif (!ksu_sel_access_fops)
\t\tksu_maybe_resolve_selinuxfs_nodes();

\tif (!ksu_sel_access_fops || !ksu_sel_access_fops->write) {
\t\tpr_info("selinux_hide: access fops missing, seqno left untouched\\n");
\t\treturn;
\t}

\tksu_access_write_fn = ksu_sel_access_fops->write;
\tif (!ksu_access_write_fn) {
\t\tpr_info("selinux_hide: access write op missing\\n");
\t\treturn;
\t}

\tret = patch_ro_slot((uintptr_t)&ksu_sel_access_fops->write,
\t\t\t    (uintptr_t)ksu_access_seqno_write);
\tpr_info("selinux_hide: access seqno fops hook ret: %d\\n", ret);
}

"""

INSERT_BEFORE = "static void ksu_init_hook_transaction_ops_write(void)"

INIT_ANCHOR = """void initialize_fake_status(void)
{
\tif (fake_status)
\t\treturn;

\tif (!ksu_prepare_fake_status_page())
\t\tfake_status = ksu_fake_status_page;
}
"""

INIT_PATCHED = """void initialize_fake_status(void)
{
\tif (fake_status)
\t\treturn;

\tif (!ksu_prepare_fake_status_page()) {
\t\tfake_status = ksu_fake_status_page;
\t\t/* SUSFS builds skip init_arm64_selinux_hide(); install what we need here */
\t\tksu_install_access_seqno_hook();
\t}
}
"""

MARK = "ksu_install_access_seqno_hook"


def patch_header(p: pathlib.Path) -> None:
    t = p.read_text(encoding="utf-8", newline="")
    if HDR_NEW in t:
        print(f"{p.name}: already patched")
        return
    if HDR_OLD not in t:
        raise SystemExit("ERROR: KSU_SELINUX_FAKE_SEQNO anchor not found")
    p.write_text(t.replace(HDR_OLD, HDR_NEW, 1), encoding="utf-8", newline="")
    print(f"{p.name}: fake seqno -> 0")


def patch_hide(p: pathlib.Path) -> None:
    t = p.read_text(encoding="utf-8", newline="")
    if MARK in t:
        print(f"{p.name}: already patched")
        return
    if INSERT_BEFORE not in t:
        raise SystemExit("ERROR: transaction hook anchor not found")
    t = t.replace(INSERT_BEFORE, HOOK + INSERT_BEFORE, 1)
    if INIT_ANCHOR not in t:
        raise SystemExit("ERROR: initialize_fake_status anchor not found")
    t = t.replace(INIT_ANCHOR, INIT_PATCHED, 1)
    p.write_text(t, encoding="utf-8", newline="")
    print(f"{p.name}: fops seqno hook added")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    base = pathlib.Path(a.src) / "kernel" / "feature"
    hide, hdr = base / "selinux_hide.c", base / "selinux_hide.h"
    for f in (hide, hdr):
        if not f.is_file():
            print(f"ERROR: missing {f}")
            return 1
    if a.check:
        t = hide.read_text(encoding="utf-8")
        print(f"selinux_hide.c: {'patched' if MARK in t else 'not patched'}")
        return 0
    patch_header(hdr)
    patch_hide(hide)
    return 0


if __name__ == "__main__":
    sys.exit(main())
