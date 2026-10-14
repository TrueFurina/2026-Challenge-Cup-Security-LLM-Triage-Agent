"""运行时产物「零污染」守卫：给外部命令套一层快照 → 比对。

用途（典型是 CI / 本地跑批）
--------------------------
    python scripts/_runtime_snapshot.py --out /tmp/rt.json      # 跑批前：存基线
    ...跑测试 / 跑批...
    python scripts/_runtime_snapshot.py --check /tmp/rt.json    # 跑批后：漂移即判红

与 `scripts/_runtime_isolation.py` 的分工
-----------------------------------------
后者是**库**：`isolated_runtime` 在自身作用域内快照 → 跑 → **必要时自动还原**，
适合「一段代码写在脚本里、同进程可控」的场景。
本脚本是**进程外的守卫**：它管不到被包裹命令的进程（尤其子进程 CLI），也无法
代为还原，只负责「事后比对并判红」。两者共用同一份受保护路径定义
（`RUNTIME_PATHS`）与同一套漂移语义（**内容 + mtime**），不维护第二份清单。

为什么 mtime 也算漂移
---------------------
写入多为**幂等重写**：内容逐字节相同、mtime 被刷新。只比内容会漏报，而对依赖
mtime 判断「盘面有没有被动过」的排查流程，mtime 被写本身已构成误导。

反空洞绿（`--self-test`）
------------------------
守卫最大的失败模式是「**静默空转**」：受保护路径被清空 / 删掉，于是永远比对
「空 vs 空」恒绿。故：
- 快照文件里一并记录当时监控的路径集合，`--check` 时集合不一致直接判红；
- `--self-test` 用纯内存构造的对照样本证明 5 类漂移（新增 / 删除 / 内容变 /
  仅 mtime 变 / 路径集合变）都能被检出——**不接触真实运行时数据**。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _runtime_isolation import PROJECT_DIR, RUNTIME_PATHS, snapshot  # noqa: E402


def _encode() -> dict:
    """把当前运行时产物编码成 JSON 可序列化形态（路径统一 `\\` → `/`，跨平台可比）。"""
    files = {}
    for rel, state in snapshot().items():
        files[rel.replace("\\", "/")] = {
            "size": len(state.content),
            "sha256": hashlib.sha256(state.content).hexdigest(),
            "mtime_ns": state.mtime_ns,
        }
    return {
        "paths": sorted(str(p).replace("\\", "/") for p in RUNTIME_PATHS),
        "files": files,
    }


def _describe(old: dict, new: dict) -> list[str]:
    """比对两份快照编码，返回人类可读的漂移描述（空列表 = 零变化）。"""
    messages: list[str] = []

    # ① 受保护路径集合变了 —— 守卫本身被削弱，这是比数据漂移更严重的问题
    if old["paths"] != new["paths"]:
        gone = sorted(set(old["paths"]) - set(new["paths"]))
        added = sorted(set(new["paths"]) - set(old["paths"]))
        if gone:
            messages.append(f"受保护路径被移除 {gone}（守卫监控面收窄 → 结论不可信）")
        if added:
            messages.append(f"受保护路径新增 {added}")

    # ② 逐个文件比对内容与 mtime
    before, after = old["files"], new["files"]
    for key in sorted(set(after) - set(before)):
        messages.append(f"新增 {key}（{after[key]['size']} 字节）")
    for key in sorted(set(before) - set(after)):
        messages.append(f"删除 {key}")
    for key in sorted(set(before) & set(after)):
        o, n = before[key], after[key]
        if o["sha256"] != n["sha256"]:
            messages.append(f"内容变化 {key}（{o['size']} → {n['size']} 字节）")
        elif o["mtime_ns"] != n["mtime_ns"]:
            messages.append(f"被重写（内容相同、mtime 变化）{key}")
    return messages


def _self_test() -> int:
    """用内存样本证明比对逻辑非空洞。**不读写真实运行时数据。**"""
    base_file = {"size": 10, "sha256": "a" * 64, "mtime_ns": 1000}
    base = {"paths": ["/p/ledger", "/p/history.jsonl"], "files": {"ledger/E1.json": dict(base_file)}}

    cases: list[tuple[str, dict, bool]] = [
        ("完全一致 → 判绿", base, False),
        ("内容变化 → 判红", {"paths": base["paths"], "files": {"ledger/E1.json": {**base_file, "sha256": "b" * 64}}}, True),
        ("仅 mtime 变 → 判红", {"paths": base["paths"], "files": {"ledger/E1.json": {**base_file, "mtime_ns": 2000}}}, True),
        ("新增文件 → 判红", {"paths": base["paths"], "files": {**base["files"], "ledger/E2.json": dict(base_file)}}, True),
        ("删除文件 → 判红", {"paths": base["paths"], "files": {}}, True),
        ("受保护路径被移除 → 判红", {"paths": ["/p/ledger"], "files": dict(base["files"])}, True),
    ]

    ok = True
    print("== 守卫自证：比对逻辑必须非空洞 ==")
    for name, sample, should_red in cases:
        red = bool(_describe(base, sample))
        good = red == should_red
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {name}: 报红={red} 期望={should_red}")

    # 监控面本身不得为空 —— 否则真实运行下会「空 vs 空」恒绿
    surface_ok = len(RUNTIME_PATHS) >= 3
    ok = ok and surface_ok
    print(f"  [{'PASS' if surface_ok else 'FAIL'}] 受保护路径非空: {len(RUNTIME_PATHS)} 个")
    for p in RUNTIME_PATHS:
        print(f"           {Path(p).relative_to(PROJECT_DIR)}")

    print(f"\n=== 守卫自证{'通过（6 类漂移均可检出）' if ok else '未通过'} ===")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="运行时产物零污染守卫")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", metavar="FILE", help="存基线快照到 FILE")
    group.add_argument("--check", metavar="FILE", help="与 FILE 比对，漂移即判红")
    group.add_argument("--self-test", action="store_true", help="证明比对逻辑非空洞（不接触真实数据）")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.out:
        data = _encode()
        Path(args.out).write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
        print(f"[基线] 受保护路径 {len(data['paths'])} 个，已有运行时产物 {len(data['files'])} 个 → {args.out}")
        return 0

    baseline_path = Path(args.check)
    if not baseline_path.is_file():
        print(f"[FAIL] 基线快照不存在：{baseline_path}（必须先跑 --out）")
        return 2
    messages = _describe(json.loads(baseline_path.read_text(encoding="utf-8")), _encode())
    if messages:
        print("== 运行时产物零污染守卫 ==")
        for line in messages:
            print(f"  [FAIL] {line}")
        print("\n=== GATE FAILED（被包裹的命令写了运行时数据）===")
        return 1
    print(f"=== GATE PASSED（受保护路径 {len(RUNTIME_PATHS)} 个，零新增 / 零改写）===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
