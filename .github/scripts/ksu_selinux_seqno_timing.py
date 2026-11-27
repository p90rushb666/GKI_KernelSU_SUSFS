#!/usr/bin/env python3
"""Two fixes for a SUSFS-built SukiSU kernel:

1. Hidden-context timing (DirtySepolicy probe)
   Under CONFIG_KSU_SUSFS the driver only sets up the fake status page, so the
   arm64 hook installer never runs. security_context_to_sid_core_fn therefore
   stays NULL and the LSM reject path is ~300 ns faster than stock's "unknown
   context" path. Resolve the symbol lazily and replay the parse+lookup cost.

2. /access avd seqno
   sel_write_access stamps every reply with the real seqno (5 after KSU loads
   policy), while the fake status page reports 0. Install the existing
   security_compute_av_user hook so both sides report 1.

Four edits:
  A. selinux_hide_arm64.c : lazy-resolve the core pointer in the replay helper
  B. selinux_hide_arm64.c : add ksu_install_access_seqno_hook() + non-arm64 stub
  C. selinux_hide.c       : status page reports 1/1 instead of 0/0
  D. selinux_hide.c       : install the access-seqno hook when the page is ready

Usage: python3 ksu_selinux_seqno_timing.py --src <SukiSU checkout>
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# ------------------------------------------------------------------ edit A --
REPLAY_NULL = """\tif (!security_context_to_sid_core_fn || !scontext || scontext_len < 8 ||
\t    scontext_len >= sizeof(buf))
\t\treturn;
"""

REPLAY_LAZY = """\t/* SUSFS builds never run the arm64 installer, so resolve it lazily */
\tif (!security_context_to_sid_core_fn) {
\t\tuintptr_t sym = kallsyms_lookup_retry("security_context_to_sid_core");

\t\tif (sym)
\t\t\tsecurity_context_to_sid_core_fn = (void *)sym;
\t}

\tif (!security_context_to_sid_core_fn || !scontext || scontext_len < 8 ||
\t    scontext_len >= sizeof(buf))
\t\treturn;
"""

# ------------------------------------------------------------------ edit B --
SEQNO_HOOK = """
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

SEQNO_STUB = """
#if !defined(CONFIG_ARM64) || !defined(CONFIG_KALLSYMS)
void ksu_install_access_seqno_hook(void) { }
#endif
"""

# ------------------------------------------------------------------ edit C --
STATUS_ANCHOR = """\tfake_status->sequence = 0;
\tfake_status->policyload = 0;
"""

STATUS_PATCHED = """\t/*
\t * Keep the status page and /access replies on the same generation: the
\t * access path reports KSU_SELINUX_FAKE_SEQNO, so the page must too, or the
\t * pair (0, 5) contradicts itself.
\t */
\tfake_status->sequence = KSU_SELINUX_FAKE_SEQNO;
\tfake_status->policyload = 1;
"""

# ------------------------------------------------------------------ edit D --
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


def patch_arm(p: pathlib.Path) -> None:
    t = p.read_text(encoding="utf-8", newline="")
    if MARK in t:
        print(f"{p.name}: already patched")
        return
    if REPLAY_NULL not in t:
        raise SystemExit("ERROR: replay helper anchor not found in selinux_hide_arm64.c")
    t = t.replace(REPLAY_NULL, REPLAY_LAZY, 1)

    tail = "#endif // ARM64 && KALLSYMS"
    i = t.rfind(tail)
    if i == -1:
        raise SystemExit("ERROR: arm64 tail marker not found")
    t = t[:i] + SEQNO_HOOK + "\n" + t[i:]
    t = t.rstrip("\n") + "\n" + SEQNO_STUB
    p.write_text(t, encoding="utf-8", newline="")
    print(f"{p.name}: lazy symbol resolve + seqno hook added")


def patch_hide(p: pathlib.Path) -> None:
    t = p.read_text(encoding="utf-8", newline="")
    if STATUS_PATCHED in t and INIT_PATCHED in t:
        print(f"{p.name}: already patched")
        return
    if STATUS_ANCHOR not in t:
        raise SystemExit("ERROR: status page anchor not found")
    if INIT_ANCHOR not in t:
        raise SystemExit("ERROR: initialize_fake_status anchor not found")
    t = t.replace(STATUS_ANCHOR, STATUS_PATCHED, 1)
    t = t.replace(INIT_ANCHOR, INIT_PATCHED, 1)
    p.write_text(t, encoding="utf-8", newline="")
    print(f"{p.name}: status page 1/1 + seqno hook install")


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
