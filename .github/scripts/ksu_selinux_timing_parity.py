#!/usr/bin/env python3
"""Equalise timing between hidden SELinux contexts and genuinely unknown ones.

DuckDetector 2026.11.27 (DirtySepolicy / "ksu_types timing"):
  the LSM hide hook rejects a hidden context before SELinux ever parses it, so
  a hidden request is consistently ~300 ns faster than a request for a context
  that really does not exist. 13,476 of 13,500 pairs landed on "hidden is
  faster", far past the 3x ratio the scanner treats as an anomaly.

Fix: before returning -EINVAL, replay the exact parse+lookup cost stock pays on
its unknown-context path. The replay uses the *original* security_context_to_sid_core
pointer with a same-length, guaranteed-unknown type name, so:
  * cost  == stock's parse + failed type lookup (same code path, same length)
  * no side effects: the result is discarded, nothing is created
  * behaviour stays identical: the caller still sees -EINVAL

Three surgical edits:
  1. selinux_hide_arm64.c : add ksu_replay_unknown_context() (uses the saved
                            original pointer, with the pre-6.4 state branch).
  2. selinux_hide.c       : call it from the setprocattr reject path.
  3. selinux_hide.c       : call it from the setxattr reject path.

Usage: python3 ksu_selinux_timing_parity.py --src <SukiSU checkout>
Exit code is non-zero when an anchor is missing, so CI fails loudly.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ARM_MARK = "ksu_replay_unknown_context"

ARM_BLOCK = """
/*
 * Pay the same parse+lookup cost stock SELinux spends on a context whose type
 * does not exist, then throw the result away. Without this the hide hook
 * short-circuits before any parsing and every hidden query is measurably
 * faster than an unknown one, which is a timing fingerprint.
 */
void ksu_replay_unknown_context(const char *scontext, u32 scontext_len)
{
\tchar buf[128];
\tsize_t i, type_start = 0, type_end = 0;
\tu32 sid = 0;
\tint colons = 0;

\tif (!security_context_to_sid_core_fn || !scontext || scontext_len < 8 ||
\t    scontext_len >= sizeof(buf))
\t\treturn;

\tmemcpy(buf, scontext, scontext_len);
\tbuf[scontext_len] = '\\0';

\t/* u:object_r:TYPE:s0  ->  keep the shape, replace TYPE with 'z' * len */
\tfor (i = 0; i < scontext_len; i++) {
\t\tif (buf[i] != ':')
\t\t\tcontinue;
\t\tif (++colons == 2)
\t\t\ttype_start = i + 1;
\t\telse if (colons == 3) {
\t\t\ttype_end = i;
\t\t\tbreak;
\t\t}
\t}
\tif (!type_start || type_end <= type_start)
\t\treturn;
\tfor (i = type_start; i < type_end; i++)
\t\tbuf[i] = 'z';

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
\textern struct selinux_state selinux_state;
\t((typeof(sh_security_context_to_sid_core) *)security_context_to_sid_core_fn)(
\t\t&selinux_state, buf, scontext_len, &sid, 0, GFP_KERNEL, 0);
#else
\t((typeof(sh_security_context_to_sid_core) *)security_context_to_sid_core_fn)(
\t\tbuf, scontext_len, &sid, 0, GFP_KERNEL, 0);
#endif
}
"""

PROC_ANCHOR = """\tpr_info_ratelimited("selinux_hide: setprocattr rejected: %.*s\\n",
\t\t\t    (int)min_t(size_t, size, 128), str);
\treturn -EINVAL;
"""

PROC_PATCHED = """\tksu_replay_unknown_context(str, (u32)size);
\tpr_info_ratelimited("selinux_hide: setprocattr rejected: %.*s\\n",
\t\t\t    (int)min_t(size_t, size, 128), str);
\treturn -EINVAL;
"""

XATTR_ANCHOR = """\tpr_info_ratelimited("selinux_hide: inode_setxattr rejected: %.*s\\n",
\t\t\t    (int)min_t(size_t, size, 128), str);
\treturn -EINVAL;
"""

XATTR_PATCHED = """\tksu_replay_unknown_context(str, (u32)size);
\tpr_info_ratelimited("selinux_hide: inode_setxattr rejected: %.*s\\n",
\t\t\t    (int)min_t(size_t, size, 128), str);
\treturn -EINVAL;
"""


def patch_arm(path: pathlib.Path) -> None:
    t = path.read_text(encoding="utf-8", newline="")
    if ARM_MARK in t:
        print(f"{path.name}: already patched")
        return
    tail = "\n#endif // ARM64 && KALLSYMS\n"
    if t.rstrip().endswith("#endif // ARM64 && KALLSYMS"):
        idx = t.rfind("\n#endif // ARM64 && KALLSYMS")
        t = t[:idx] + "\n" + ARM_BLOCK + t[idx:]
    else:
        raise SystemExit("ERROR: selinux_hide_arm64.c tail anchor not found")
    stub = (
        "\n#if !defined(CONFIG_ARM64) || !defined(CONFIG_KALLSYMS)\n"
        "void ksu_replay_unknown_context(const char *scontext, u32 scontext_len) { }\n"
        "#endif\n"
    )
    path.write_text(t + stub, encoding="utf-8", newline="")
    print(f"{path.name}: replay helper added (stub for non-arm64)")


def patch_hide(path: pathlib.Path) -> None:
    t = path.read_text(encoding="utf-8", newline="")
    hits = 0
    for anchor, patched, label in (
        (PROC_ANCHOR, PROC_PATCHED, "setprocattr"),
        (XATTR_ANCHOR, XATTR_PATCHED, "setxattr"),
    ):
        if patched in t:
            print(f"{path.name}: {label} already patched")
            continue
        if anchor not in t:
            raise SystemExit(f"ERROR: selinux_hide.c {label} anchor not found")
        t = t.replace(anchor, patched, 1)
        hits += 1
        print(f"{path.name}: {label} replay added")
    if hits:
        path.write_text(t, encoding="utf-8", newline="")
    if not hits:
        print(f"{path.name}: already patched")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    base = pathlib.Path(a.src) / "kernel" / "feature"
    arm = base / "selinux_hide_arm64.c"
    hide = base / "selinux_hide.c"
    for p in (arm, hide):
        if not p.is_file():
            print(f"ERROR: missing {p}")
            return 1
    if a.check:
        for p in (arm, hide):
            txt = p.read_text(encoding="utf-8", newline="")
            print(f"{p.name}: {'patched' if ARM_MARK in txt else 'not patched'}")
        return 0
    patch_arm(arm)
    patch_hide(hide)
    return 0


if __name__ == "__main__":
    sys.exit(main())
