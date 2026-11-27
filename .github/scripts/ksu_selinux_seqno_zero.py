#!/usr/bin/env python3
"""Make the SELinux status/access numbers look like a stock device: all zero.

Why zero:
  selinuxfs creates /status lazily, so on a stock phone sequence/policyload read
  0 unless policy is reloaded afterwards; /access reports the same generation.
  Anything non-zero (1/1/1 or 0/0/5) is evidence that policy was rewritten.

What this does (three edits, no replay, no timing hacks):
  A. selinux_hide_arm64.c : ksu_install_access_seqno_hook() -> patches
                            sel_write_access -> security_compute_av_user
  B. selinux_hide_arm64.c : sh_swap_seqno() writes 0 instead of 1
  C. selinux_hide.c       : install the hook once the fake status page exists

The status page itself keeps the upstream 0/0 defaults, so all three values agree.

Usage: python3 ksu_selinux_seqno_zero.py --src <SukiSU checkout>
"""

from __future__ import annotations

import argparse
import pathlib
import sys

HOOK = """
void ksu_install_access_seqno_hook(void)
{
\tuintptr_t target_callsite = kallsyms_lookup_retry("sel_write_access");
\tuintptr_t symbol_addr = kallsyms_lookup_retry("security_compute_av_user");
\tint ret;

\tif (!target_callsite || !symbol_addr) {
\t\tpr_info("selinux_hide: access seqno hook skipped, symbols missing\\n");
\t\treturn;
\t}

\tret = patch_arm64_branches_trampolined(target_callsite, symbol_addr,
\t\t\t\t\t       (uintptr_t)&sh_security_compute_av_user);
\tpr_info("selinux_hide: hook_site: sel_write_access->security_compute_av_user ret: %d\\n", ret);
}
"""

STUB = """
#if !defined(CONFIG_ARM64) || !defined(CONFIG_KALLSYMS)
void ksu_install_access_seqno_hook(void) { }
#endif
"""

SEQNO_ANCHOR = "\tavd->seqno = KSU_SELINUX_FAKE_SEQNO;\n"
SEQNO_PATCHED = "\tavd->seqno = 0;\n"

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


def patch_arm(path: pathlib.Path) -> None:
    t = path.read_text(encoding="utf-8", newline="")
    if MARK in t:
        print(f"{path.name}: already patched")
        return
    if SEQNO_ANCHOR not in t:
        raise SystemExit("ERROR: sh_swap_seqno anchor not found")
    t = t.replace(SEQNO_ANCHOR, SEQNO_PATCHED, 1)

    tail = "#undef patch_arm64_branches_trampolined"
    i = t.rfind(tail)
    if i == -1:
        raise SystemExit("ERROR: arm64 #undef marker not found")
    t = t[:i] + HOOK + "\n" + t[i:]
    t = t.rstrip("\n") + "\n" + STUB
    path.write_text(t, encoding="utf-8", newline="")
    print(f"{path.name}: seqno -> 0, access hook added")


def patch_hide(path: pathlib.Path) -> None:
    t = path.read_text(encoding="utf-8", newline="")
    if INIT_PATCHED in t:
        print(f"{path.name}: already patched")
        return
    if INIT_ANCHOR not in t:
        raise SystemExit("ERROR: initialize_fake_status anchor not found")
    t = t.replace(INIT_ANCHOR, INIT_PATCHED, 1)
    path.write_text(t, encoding="utf-8", newline="")
    print(f"{path.name}: install hook with the status page")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    base = pathlib.Path(a.src) / "kernel" / "feature"
    arm, hide = base / "selinux_hide_arm64.c", base / "selinux_hide.c"
    for f in (arm, hide):
        if not f.is_file():
            print(f"ERROR: missing {f}")
            return 1
    if a.check:
        for f in (arm, hide):
            print(f"{f.name}: {'patched' if MARK in f.read_text(encoding='utf-8') else 'not patched'}")
        return 0
    patch_arm(arm)
    patch_hide(hide)
    return 0


if __name__ == "__main__":
    sys.exit(main())
