#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Performance benchmarks for snowland-smx (pysmx) compared with gmssl.

This script measures throughput (MB/s) and operations-per-second for the
SM2 / SM3 / SM4 and ZUC implementations shipped in pysmx, and -- when the
third-party ``gmssl`` / ``gmssl-pyx`` packages are installed -- the equivalent
routines from those libraries, so they can be compared side by side.

``gmssl`` (https://pypi.org/project/gmssl/) and ``gmssl-pyx``
(https://pypi.org/project/gmssl-pyx/, a Cython wrapper of the GmSSL C
library) are optional dependencies. Install them with ``pip install gmssl
gmssl-pyx`` to enable the comparison columns. When neither is available the
script still runs and reports pysmx numbers only.

Usage:
    python scripts/benchmark.py                 # run every benchmark
    python scripts/benchmark.py sm3 sm4         # run only the listed algorithms
    python scripts/benchmark.py --json out.json # also dump raw numbers to JSON
    python scripts/benchmark.py --quick         # smaller data sizes, faster run
    python scripts/benchmark.py --md doc/benchmark.md  # write a Markdown report

Supported algorithm selectors: sm2, sm3, sm4, zuc
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from time import perf_counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ---------------------------------------------------------------------------
# gmssl availability (optional comparison baseline #1)
# ---------------------------------------------------------------------------
try:
    import gmssl  # noqa: F401
    from gmssl import sm3 as _g_sm3
    from gmssl.sm4 import CryptSM4 as _GSm4  # noqa: F401
    from gmssl.sm4 import SM4_ENCRYPT as _G_SM4_ENCRYPT  # noqa: F401
    from gmssl.sm4 import SM4_DECRYPT as _G_SM4_DECRYPT  # noqa: F401
    from gmssl.sm2 import CryptSM2 as _GSm2  # noqa: F401
    HAVE_GMSSL = True
    _GMSSL_ERROR = None
except Exception as _exc:  # pragma: no cover - depends on environment
    HAVE_GMSSL = False
    _GMSSL_ERROR = _exc

# ---------------------------------------------------------------------------
# gmssl-pyx availability (optional comparison baseline #2, Cython/GmSSL C)
# ---------------------------------------------------------------------------
try:
    import gmssl_pyx  # noqa: F401
    from gmssl_pyx import sm3_hash as _px_sm3_hash
    from gmssl_pyx import (  # noqa: F401
        sm2_key_generate as _px_sm2_keygen,
        sm2_encrypt as _px_sm2_encrypt,
        sm2_decrypt as _px_sm2_decrypt,
        sm2_sign as _px_sm2_sign,
        sm2_verify as _px_sm2_verify,
        sm4_cbc_padding_encrypt as _px_sm4_cbc_encrypt,
        sm4_cbc_padding_decrypt as _px_sm4_cbc_decrypt,
    )
    HAVE_PYX = True
    _PX_ERROR = None
except Exception as _exc:  # pragma: no cover - depends on environment
    HAVE_PYX = False
    _PX_ERROR = _exc

# ---------------------------------------------------------------------------
# pysmx imports (fail fast if the package is broken)
# ---------------------------------------------------------------------------
from pysmx.SM3 import hexdigest as sm3_hexdigest  # noqa: E402
from pysmx.SM4._SM4 import Sm4  # noqa: E402
from pysmx.block_cyphers import ENCRYPT as SM4_ENCRYPT  # noqa: E402
from pysmx.block_cyphers import DECRYPT as SM4_DECRYPT  # noqa: E402
from pysmx.SM2 import (  # noqa: E402
    generate_keypair,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
)
from pysmx.SM3 import hexdigest as _sm3_hex  # noqa: E402
from pysmx.SM2._SM2 import get_random_str  # noqa: E402
from pysmx.ZUC import ZUC  # noqa: E402


# ---------------------------------------------------------------------------
# Timing helper: adaptively choose the iteration count (~ target seconds)
# ---------------------------------------------------------------------------
def _autorange(op, target=0.1, max_iters=50000):
    op()  # warmup
    n = 1
    while True:
        t0 = perf_counter()
        for _ in range(n):
            op()
        dt = perf_counter() - t0
        if dt >= target or n >= max_iters:
            return n, dt


def _measure(op, size_bytes):
    n, dt = _autorange(op)
    ops = n / dt if dt > 0 else float("inf")
    mbps = (n * size_bytes) / dt / (1024.0 * 1024.0) if dt > 0 else float("inf")
    return ops, mbps


def _fmt_size(n):
    if n >= 1024 * 1024:
        return "%d MB" % (n // (1024 * 1024))
    if n >= 1024:
        return "%d KB" % (n // 1024)
    return "%d B" % n


def _fmt_num(x):
    if x == float("inf"):
        return "n/a"
    if x >= 1e6:
        return "%.2fM" % (x / 1e6)
    if x >= 1e3:
        return "%.1fk" % (x / 1e3)
    return "%.1f" % x


# ---------------------------------------------------------------------------
# Data sets
# ---------------------------------------------------------------------------
SIZES_FULL = [64, 1024, 64 * 1024, 1024 * 1024]
SIZES_QUICK = [64, 1024, 16 * 1024]
# SM2 plaintext size: must stay <= 255 bytes (gmssl-pyx sm2_encrypt limit)
SM2_PLAIN_SIZE = 64


# ---------------------------------------------------------------------------
# Comparison library registry (label -> factory map)
# Each factory takes the payload size (in bytes) and returns a zero-argument
# callable that performs one operation on a payload of that size.
# ---------------------------------------------------------------------------
COMPARISONS = []  # list of (label, {(algo, op): factory})


def _build_gmssl_ops():
    """Register gmssl (pure-Python) comparison operations."""
    if not HAVE_GMSSL:
        return

    key16 = b"0123456789abcdef"
    iv16 = b"abcdef0123456789"

    def _g_sm3_op(size):
        data = b"A" * size

        def op():
            # gmssl sm3_hash mutates its input (appends padding), so a fresh
            # list of integers must be supplied on every call.
            return _g_sm3.sm3_hash(list(data))

        return op

    g_enc = _GSm4()
    g_enc.set_key(key16, _G_SM4_ENCRYPT)
    g_dec = _GSm4()
    g_dec.set_key(key16, _G_SM4_DECRYPT)

    def _g_sm4_ecb_enc(size):
        data = b"A" * size

        def op():
            return g_enc.crypt_ecb(data)

        return op

    def _g_sm4_ecb_dec(size):
        data = b"A" * size
        ct = g_enc.crypt_ecb(data)

        def op():
            return g_dec.crypt_ecb(ct)

        return op

    def _g_sm4_cbc_enc(size):
        data = b"A" * size

        def op():
            return g_enc.crypt_cbc(iv16, data)

        return op

    def _g_sm4_cbc_dec(size):
        data = b"A" * size
        ct = g_enc.crypt_cbc(iv16, data)

        def op():
            return g_dec.crypt_cbc(iv16, ct)

        return op

    # SM2 (fixed-size message; size arg ignored) -- reuse pysmx keys
    pk, sk = generate_keypair(64)
    g_sm2 = _GSm2(public_key=pk.hex(), private_key=sk.hex())
    sm2_msg = b"A" * SM2_PLAIN_SIZE
    sm2_ct = g_sm2.encrypt(sm2_msg)
    g_sig = g_sm2.sign(sm2_msg, get_random_str(64))

    def _g_sm2_enc(size):
        def op():
            return g_sm2.encrypt(sm2_msg)

        return op

    def _g_sm2_dec(size):
        def op():
            return g_sm2.decrypt(sm2_ct)

        return op

    def _g_sm2_sign(size):
        def op():
            return g_sm2.sign(sm2_msg, get_random_str(64))

        return op

    def _g_sm2_verify(size):
        def op():
            return g_sm2.verify(g_sig, sm2_msg)

        return op

    COMPARISONS.append(("gmssl", {
        ("sm3", "hash"): _g_sm3_op,
        ("sm4", "ecb_encrypt"): _g_sm4_ecb_enc,
        ("sm4", "ecb_decrypt"): _g_sm4_ecb_dec,
        ("sm4", "cbc_encrypt"): _g_sm4_cbc_enc,
        ("sm4", "cbc_decrypt"): _g_sm4_cbc_dec,
        ("sm2", "encrypt"): _g_sm2_enc,
        ("sm2", "decrypt"): _g_sm2_dec,
        ("sm2", "sign"): _g_sm2_sign,
        ("sm2", "verify"): _g_sm2_verify,
    }))


def _build_pyx_ops():
    """Register gmssl-pyx (Cython/GmSSL C) comparison operations.

    gmssl-pyx exposes a functional API and only supports SM4 in CBC mode
    (no ECB), so only CBC operations are registered here.
    """
    if not HAVE_PYX:
        return

    key16 = b"0123456789abcdef"
    iv16 = b"abcdef0123456789"

    def _px_sm3_op(size):
        data = b"A" * size

        def op():
            return _px_sm3_hash(data)

        return op

    def _px_sm4_cbc_enc(size):
        data = b"A" * size

        def op():
            return _px_sm4_cbc_encrypt(key16, iv16, data)

        return op

    def _px_sm4_cbc_dec(size):
        data = b"A" * size
        ct = _px_sm4_cbc_encrypt(key16, iv16, data)

        def op():
            return _px_sm4_cbc_decrypt(key16, iv16, ct)

        return op

    # SM2 (fixed-size message; size arg ignored) -- own keypair
    pk, sk = _px_sm2_keygen()
    sm2_msg = b"A" * SM2_PLAIN_SIZE
    sm2_ct = _px_sm2_encrypt(pk, sm2_msg)
    sm2_sig = _px_sm2_sign(sk, pk, sm2_msg)

    def _px_sm2_enc(size):
        def op():
            return _px_sm2_encrypt(pk, sm2_msg)

        return op

    def _px_sm2_dec(size):
        def op():
            return _px_sm2_decrypt(sk, sm2_ct)

        return op

    def _px_sm2_sign_op(size):
        def op():
            return _px_sm2_sign(sk, pk, sm2_msg)

        return op

    def _px_sm2_verify_op(size):
        def op():
            return _px_sm2_verify(pk, sm2_msg, sm2_sig)

        return op

    COMPARISONS.append(("gmssl-pyx", {
        ("sm3", "hash"): _px_sm3_op,
        ("sm4", "cbc_encrypt"): _px_sm4_cbc_enc,
        ("sm4", "cbc_decrypt"): _px_sm4_cbc_dec,
        ("sm2", "encrypt"): _px_sm2_enc,
        ("sm2", "decrypt"): _px_sm2_dec,
        ("sm2", "sign"): _px_sm2_sign_op,
        ("sm2", "verify"): _px_sm2_verify_op,
    }))


# ---------------------------------------------------------------------------
# pysmx benchmark routines
# ---------------------------------------------------------------------------
def _bench_one(algo, op_name, op, size_bytes, results):
    """Benchmark one operation for pysmx and every available comparison lib."""
    ops, mbps = _measure(op, size_bytes)
    results.append({
        "algo": algo,
        "op": op_name,
        "size": size_bytes,
        "lib": "pysmx",
        "ops_per_s": ops,
        "mb_per_s": mbps,
    })
    for label, ops_map in COMPARISONS:
        factory = ops_map.get((algo, op_name))
        if factory is None:
            continue
        try:
            gop = factory(size_bytes)
            gops, gmbps = _measure(gop, size_bytes)
            results.append({
                "algo": algo,
                "op": op_name,
                "size": size_bytes,
                "lib": label,
                "ops_per_s": gops,
                "mb_per_s": gmbps,
            })
        except Exception as _e:  # pragma: no cover
            sys.stderr.write(
                "  [warn] %s %s/%s failed: %s\n" % (label, algo, op_name, _e)
            )


def bench_sm3(results, sizes):
    for size in sizes:
        data = b"A" * size

        def _p_sm3(d=data):
            return sm3_hexdigest(d)

        _bench_one("sm3", "hash", _p_sm3, size, results)


def bench_sm4(results, sizes):
    key16 = b"0123456789abcdef"
    iv16 = b"abcdef0123456789"

    enc = Sm4()
    enc.set_key(key16, SM4_ENCRYPT)
    dec = Sm4()
    dec.set_key(key16, SM4_DECRYPT)

    for size in sizes:
        data = b"A" * size
        ct = enc.crypt_ecb(data)

        def _p_ecb_enc(d=data):
            return enc.crypt_ecb(d)

        def _p_ecb_dec(c=ct):
            return dec.crypt_ecb(c)

        _bench_one("sm4", "ecb_encrypt", _p_ecb_enc, size, results)
        _bench_one("sm4", "ecb_decrypt", _p_ecb_dec, size, results)

        cbc_ct = enc.crypt_cbc(iv16, data)

        def _p_cbc_enc(d=data):
            return enc.crypt_cbc(iv16, d)

        def _p_cbc_dec(c=cbc_ct):
            return dec.crypt_cbc(iv16, c)

        _bench_one("sm4", "cbc_encrypt", _p_cbc_enc, size, results)
        _bench_one("sm4", "cbc_decrypt", _p_cbc_dec, size, results)


def bench_sm2(results, sizes):
    pk, sk = generate_keypair(64)
    msg = b"A" * SM2_PLAIN_SIZE
    ct = Encrypt(msg, pk, 64)
    sm2_msg_str = msg.decode("latin-1")
    e = _sm3_hex(sm2_msg_str)
    sig = Sign(e, sk, get_random_str(64), 64, Hexstr=1)

    def _p_keygen():
        return generate_keypair(64)

    def _p_enc():
        return Encrypt(msg, pk, 64)

    def _p_dec():
        return Decrypt(ct, sk, 64)

    def _p_sign():
        return Sign(e, sk, get_random_str(64), 64, Hexstr=1)

    def _p_verify():
        return Verify(sig, e, pk, 64, Hexstr=1)

    # keygen has no meaningful data size -> report ops only
    kops, _ = _measure(_p_keygen, 0)
    results.append({
        "algo": "sm2",
        "op": "keygen",
        "size": 0,
        "lib": "pysmx",
        "ops_per_s": kops,
        "mb_per_s": 0.0,
    })

    _bench_one("sm2", "encrypt", _p_enc, SM2_PLAIN_SIZE, results)
    _bench_one("sm2", "decrypt", _p_dec, SM2_PLAIN_SIZE, results)
    _bench_one("sm2", "sign", _p_sign, len(msg), results)
    _bench_one("sm2", "verify", _p_verify, len(msg), results)


def bench_zuc(results, sizes):
    key = [0] * 16
    iv = [0] * 16

    for size in sizes:
        data = b"A" * size

        def _p_zuc(d=data):
            z = ZUC(key, iv)
            return list(z.zuc_encrypt(d))

        _bench_one("zuc", "encrypt", _p_zuc, size, results)
    # gmssl / gmssl-pyx have no ZUC implementation -> no comparison column


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _print_algo(algo, rows, comparisons):
    print("\n%s" % ("=" * 64))
    print("  %s" % algo.upper())
    print("%s" % ("=" * 64))
    print("%-10s %-12s %14s %14s   %s" %
          ("size", "lib", "ops/s", "MB/s", "speedup"))
    print("-" * 64)
    seen = []
    for r in rows:
        key = (r["op"], r["size"])
        if key not in seen:
            seen.append(key)
    pmap = {(r["op"], r["size"]): r for r in rows if r["lib"] == "pysmx"}
    cmap = {}
    for label, _ in comparisons:
        cmap[label] = {(r["op"], r["size"]): r
                       for r in rows if r["lib"] == label}
    for (op, size) in seen:
        prow = pmap.get((op, size))
        if prow is None:
            continue
        print("%-10s %-12s %14s %14s" % (
            _fmt_size(size), "pysmx",
            _fmt_num(prow["ops_per_s"]),
            _fmt_num(prow["mb_per_s"]),
        ))
        for label, _ in comparisons:
            grow = cmap[label].get((op, size))
            if grow is not None:
                if prow["mb_per_s"] > 0 and grow["mb_per_s"] > 0:
                    spd = "%.2fx" % (prow["mb_per_s"] / grow["mb_per_s"])
                else:
                    spd = "-"
                print("%-10s %-12s %14s %14s   %s" % (
                    "", label,
                    _fmt_num(grow["ops_per_s"]),
                    _fmt_num(grow["mb_per_s"]),
                    spd,
                ))


def _md_table(rows, comparisons):
    """Render one Markdown table for a set of (op, size) rows."""
    header = ["operation", "size", "ops/s", "MB/s", "speedup (vs pysmx)"]
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join([" --- "] * len(header)) + "|"]
    seen = []
    for r in rows:
        key = (r["op"], r["size"])
        if key not in seen:
            seen.append(key)
    pmap = {(r["op"], r["size"]): r for r in rows if r["lib"] == "pysmx"}
    cmap = {}
    for label, _ in comparisons:
        cmap[label] = {(r["op"], r["size"]): r
                       for r in rows if r["lib"] == label}
    for (op, size) in seen:
        prow = pmap.get((op, size))
        if prow is None:
            continue
        size_disp = "-" if size == 0 else _fmt_size(size)
        out.append("| %s | %s | %s | %s | - |" % (
            op, size_disp,
            _fmt_num(prow["ops_per_s"]),
            _fmt_num(prow["mb_per_s"]),
        ))
        for label, _ in comparisons:
            grow = cmap[label].get((op, size))
            if grow is not None:
                if prow["mb_per_s"] > 0 and grow["mb_per_s"] > 0:
                    spd = "%.2fx" % (prow["mb_per_s"] / grow["mb_per_s"])
                else:
                    spd = "-"
                out.append("| %s | | %s | %s | %s |" % (
                    label,
                    _fmt_num(grow["ops_per_s"]),
                    _fmt_num(grow["mb_per_s"]),
                    spd,
                ))
    return out


def _render_markdown(results, sizes, comparisons, python_version):
    """Render the full benchmark results as a Markdown document string."""
    L = []
    L.append("# snowland-smx 性能对比（pysmx vs gmssl / gmssl-pyx）")
    L.append("")
    L.append("本文档由 `scripts/benchmark.py` 自动生成，请勿手动修改。")
    L.append("")
    L.append("## 测试环境")
    L.append("")
    L.append("- Python: %s" % python_version)
    if comparisons:
        for label, _ in comparisons:
            L.append("- 对比库 %s: 已启用" % label)
    else:
        L.append("- 对比库: 无（仅 pysmx）")
    size_str = " / ".join(_fmt_size(s) for s in sizes)
    L.append("- 数据规模: %s" % size_str)
    L.append("- 生成时间: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    L.append("- 复现命令: `py scripts/benchmark.py --quick`")
    L.append("")
    L.append("> speedup = pysmx MB/s ÷ 对比库 MB/s")
    L.append("")
    L.append("> 注：gmssl-pyx 的 SM4 仅提供 CBC 模式（无 ECB），"
             "且其 SM2 明文上限为 255 字节，故 SM2 基准统一使用 %d 字节明文。"
             % SM2_PLAIN_SIZE)
    L.append("")
    algos = []
    for r in results:
        if r["algo"] not in algos:
            algos.append(r["algo"])
    for algo in algos:
        rows = [r for r in results if r["algo"] == algo]
        L.append("## %s" % algo.upper())
        L.append("")
        if algo == "sm4":
            for grp, label in (("ecb", "ECB"), ("cbc", "CBC")):
                L.append("### %s" % label)
                L.append("")
                L.extend(_md_table(
                    [r for r in rows if r["op"].startswith(grp)], comparisons))
                L.append("")
        else:
            L.extend(_md_table(rows, comparisons))
            L.append("")
    return "\n".join(L)


def _run(algo, results, sizes, comparisons):
    dispatch = {
        "sm2": bench_sm2,
        "sm3": bench_sm3,
        "sm4": bench_sm4,
        "zuc": bench_zuc,
    }
    fn = dispatch[algo]
    algo_rows = []
    fn(algo_rows, sizes)
    _print_algo(algo, algo_rows, comparisons)
    results.extend(algo_rows)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Benchmark pysmx against gmssl / gmssl-pyx"
    )
    parser.add_argument(
        "algorithms", nargs="*",
        choices=["sm2", "sm3", "sm4", "zuc"],
        help="algorithms to benchmark (default: all)",
    )
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write raw results to this JSON file")
    parser.add_argument("--md", dest="md_path", default="doc/benchmark.md",
                        help="write a Markdown report to this path "
                             "(default: doc/benchmark.md)")
    parser.add_argument("--quick", action="store_true",
                        help="use smaller data sizes for a faster run")
    args = parser.parse_args(argv)

    selected = args.algorithms or ["sm2", "sm3", "sm4", "zuc"]
    sizes = SIZES_QUICK if args.quick else SIZES_FULL

    COMPARISONS.clear()
    print("snowland-smx (pysmx) performance benchmark")
    print("Python: %s" % sys.version.split()[0])
    if HAVE_GMSSL:
        print("gmssl : available -> comparison ENABLED")
        _build_gmssl_ops()
    else:
        print("gmssl : NOT installed -> skipped")
        if _GMSSL_ERROR is not None:
            sys.stderr.write("  [debug] gmssl import error: %s\n" %
                             _GMSSL_ERROR)
    if HAVE_PYX:
        print("gmssl-pyx : available -> comparison ENABLED")
        _build_pyx_ops()
    else:
        print("gmssl-pyx : NOT installed -> skipped")
        if _PX_ERROR is not None:
            sys.stderr.write("  [debug] gmssl-pyx import error: %s\n" %
                             _PX_ERROR)

    if "zuc" in selected:
        print("note  : gmssl / gmssl-pyx have no ZUC implementation; "
              "ZUC is benchmarked for pysmx only")

    results = []
    for algo in selected:
        try:
            _run(algo, results, sizes, COMPARISONS)
        except Exception as _e:  # pragma: no cover
            sys.stderr.write("benchmark %s failed: %s\n" % (algo, _e))

    if args.json_path:
        with open(args.json_path, "w") as fh:
            json.dump(results, fh, indent=2)
        print("\nraw results written to %s" % args.json_path)

    if args.md_path:
        md = _render_markdown(results, sizes, COMPARISONS,
                              sys.version.split()[0])
        with open(args.md_path, "w", encoding="utf-8") as fh:
            fh.write(md)
        print("markdown report written to %s" % args.md_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
