# snowland-smx-python 代码不足与改进计划

> 本文档对 `snowland-smx-python` 整个仓库（不限于 benchmark 对比脚本）进行代码质量、
> 安全性、测试、性能、工程化与文档等方面的审视，并给出分阶段的改进路线图。
> 所有结论均基于仓库当前代码，附文件路径与行号作为证据。

分析范围：`pysmx/`（SM2/SM3/SM4/SM9/ZUC 及 backend/block_cyphers/ciphers/common/crypto/ecc/extra）
`setup.py` / `pyproject.toml` / `requirements*.txt` / `.github/workflows/test.yml` / `scripts/run_smx_tests.py`
及 `doc/`、`demo/`。

---

## 1. 关键不足（按优先级排列）

### P0 — 安全问题（Critical，需优先修复）

#### 1.1 SM2 私钥与加密临时值使用非密码学安全随机数
- 证据：
  - `pysmx/SM2/_SM2.py:10` —— `from random import choices, randint`
  - `pysmx/SM2/_SM2.py:77-78` —— `get_random_str` 内部使用 `random.choices`（Mersenne Twister）
  - `pysmx/SM2/_SM2.py:421` —— `Encrypt` 中 `k = get_random_str(len_para)`（SM2 加密临时随机数）
  - `pysmx/SM2/_SM2.py:501` —— `generate_keypair` 中 `d = get_random_str(len_param)`（私钥）
  - `pysmx/SM2/__init__.py:9-11` —— 默认导出的是 `_SM2` 纯 Python 实现（即上述不安全路径）
- 影响：
  - Mersenne Twister 是可预测的 PRNG，其状态可由少量输出反推。用其生成 SM2 私钥 `d`
    或可枚举恢复；用其生成加密临时值 `k` 可能泄露明文乃至私钥。
  - 违反国密规范（GM/T 0003、GM/T 0009）对随机数发生器的要求（应使用经认证的
    密码学安全随机数发生器，CSPRNG）。
- 一致性矛盾：同仓库 `pysmx/SM9/_SM9.py:1351,1358` 与 `pysmx/extra/envelope.py:96,100`
  已正确使用 `os.urandom`，唯独 SM2 未统一。
- 状态：✅ 已修复（待提交）。`get_random_str` 改用 `secrets`（CSPRNG），并将随机值约束到
  `[1, sm2_N-1]`（符合 GM/T 0003）；同时移除 `random` 导入与无用 `letterlist`。
  `is_prime` 的 Miller-Rabin 基数也改用 `secrets`。新增 3 个回归测试
  （`test_random_source_secure_range` / `test_random_source_not_constant` /
  `test_keypair_private_key_in_range`），全量 105 测试通过。

#### 1.2 `pysmx/crypto/hashlib.py` 整体复刻标准库 hashlib
- 证据：`pysmx/crypto/hashlib.py` 复制了 CPython `hashlib` 实现，并直接 `import _sha1`/
  `_md5`/`_sha256`/`_sha3` 等 CPython 内部 C 模块（line 34-60, 113-119）。
- 影响：
  - 在非 CPython 实现（如 PyPy）或裁剪环境中会 `ImportError`，健壮性差。
  - 重复造轮子，长期维护负担重；标准库已提供全部算法，仅需补充 SM3。

### P1 — 正确性与健壮性

#### 1.3 `ecc/fq.py` 裸 `except:` 与 py2 兼容残留
- 证据：`pysmx/ecc/fq.py:12-16` —— `try: foo = long except: long = int`。
- 影响：裸 `except:` 会吞掉 `KeyboardInterrupt`/`SystemExit` 等，属于 Python 反模式；
  `long` 是 Python 2 残留，说明代码仍保留 py2/py3 兼容壳。

#### 1.4 `backend/_backend.py` 注册了未实现的 backend 接口
- 证据：`pysmx/backend/_backend.py:31-33` —— 将 `PysmxBackend` 注册为 cryptography 的
  `CipherBackend`/`HMACBackend`，但本仓库并未实现通用 Cipher/HMAC backend。
- 影响：可能误导调用方以为 pysmx 提供了通用对称加密/HMAC 后端，实际缺失，易触发异常。

#### 1.5 异常类型缺乏体系
- 现状：代码中多直接 `raise ValueError(...)`，缺少如 `InvalidKeyError`/`DecryptionError`/
  `SignError` 等语义化自定义异常。
- 影响：上层难以区分"参数错误"与"解密失败"，不利于组合使用与错误处理。

### P2 — 测试覆盖

#### 1.6 大量模块无独立单元测试
- 覆盖现状：`pysmx/test/` 含 SM2/SM3/SM4(含 block_cyphers/stream)/SM9/ZUC/padding/ccn。
- 缺失：
  - `pysmx/extra/envelope.py`（数字信封）——无测试。
  - `pysmx/ecc/`（ate/ec/fq）——仅经 SM9 间接覆盖，无独立单测。
  - `pysmx/ciphers/algorithm`、`pysmx/crypto/hashlib`（pbkdf2_hmac 等）、`pysmx/backend`。
  - `pysmx/common/_padding.py`、`_common.py` 边界与异常路径。

#### 1.7 测试发现机制脆弱
- 证据：`scripts/run_smx_tests.py:13-19` 手工逐个 import 测试类；新增测试文件若未在此登记则不会运行。
- 影响：CI 仅运行被手工登记的用例，新测试易被遗漏。

#### 1.8 缺少性能回归与异常路径测试
- 现状：性能仅由 `scripts/benchmark.py` 生成报告，CI 不对其做断言（无"性能回退即失败"）。
- 影响：无法防止性能劣化；边界值、错误密钥、错误密文等异常路径缺少系统化测试。

#### 1.9 无覆盖率度量
- 影响：维护者无法量化测试充分性，重构时风险不可见。

### P3 — 性能

#### 1.10 纯 Python 实现，无加速后端
- 证据：`scripts/benchmark.py` 结果：SM4 约 6–9 ops/s（16KB），明显慢于 `gmssl-pyx`（Cython/C）；
  SM2/SM9 大整数虽借助内置 `pow`，但点运算、字段运算仍全 Python。
- 影响：无法用于高吞吐生产场景。

#### 1.11 冗余实现
- 证据：`pysmx/SM2/_SM2.py:36-50` —— `modular_power` 是 `pow(a,n,p)` 的递归包装，保留了
  递归签名的无用注释，可直接使用内置 `pow`。
- 影响：可读性差，且递归在大指数下有栈风险（虽当前直接 return pow）。

### P4 — 工程化、打包与 CI

#### 1.12 Python 版本声明与实际不符
- 证据：`setup.py:58-68` classifiers 列出 `2.7`/`3.6`/`3.7`，但代码使用 f-string、
  py3 import 风格，且 `ecc/fq.py` 仍带 py2 兼容壳；CI 矩阵（`test.yml:21-27`）仅 `3.8–3.13`。
- 影响：用户误以为支持 2.7，实际不支持。

#### 1.13 未迁移到 `pyproject.toml` 的 `[project]` 元数据
- 证据：`pyproject.toml` 仅含 `build-system`，元数据全在 `setup.py`。
- 影响：不符合 PEP 621 现代打包惯例，工具链（如 `python -m build`）元数据分散。

#### 1.14 依赖管理不清晰
- 证据：
  - `requirements.txt`：`cryptography`（运行时唯一依赖）。
  - `test_requirements.txt`：`astartool>=0.0.2`（用途不明，疑似某 demo/test 专用）、`gmssl`
    （benchmark 可选，却被列为 test 必装）。
- 影响：测试/基准/运行时依赖混在一起，安装面过大；`extras_require` 已定义但未充分利用。

#### 1.15 CI 缺少质量门禁
- 现状：`test.yml` 仅 `scripts/run_smx_tests.py` + benchmark 生成 md。
- 缺失：lint（ruff/flake8）、类型检查（mypy）、安全扫描（bandit）、覆盖率、benchmark 性能回归断言。

#### 1.16 编译产物遗留
- 证据：工作区存在 48 个 `.pyc`（`.gitignore` 已含 `*.py[cod]`，应未被提交，但本地遗留）。
- 影响：仓库卫生；建议清理并确认无被追踪。

### P5 — API 设计与文档

#### 1.17 API 风格不统一
- SM2：`Encrypt/Decrypt/Sign/Verify`（camelCase，位置参数，低层参数 `len_para`/`Hexstr`）。
- SM3：`hexdigest`（snake_case，类标准库 hashlib）。
- SM4：`Sm4().crypt_ecb`（面向对象）与 `sm4_encrypt_ecb`（函数式，来自 crypto 后端）并存。
- 缺少统一高层 API（如 `sm2_encrypt(pk, msg)` 风格），调用方式割裂。

#### 1.18 子模块导出不完整
- 证据：`pysmx/extra/__init__.py` 为空，`envelope` 未被导出，需深层 import
  （`from pysmx.extra.envelope import ...`）。

#### 1.19 文档缺口
- 现有：`README.md`/`README.en.md`、`doc/v1.0.0post1`、`doc/v1.0.1`（API 文档）、
  `doc/benchmark.md`。
- 缺失：
  - 安全模型与限制说明（尤其 SM2 随机数风险、性能定位）。
  - 贡献指南（CONTRIBUTING）、安全漏洞上报（SECURITY.md）。
  - "推荐后端"指引（何时用 `_SM2` 纯 Python vs `_cryptography` 绑定）。
  - 与最新代码的 CHANGELOG 对应（`__version__ = 1.0.1`）。

#### 1.20 缺少类型注解与系统化 docstring
- 现状：仅有零星 `: int`，docstring 稀疏。
- 影响：IDE 提示弱、mypy 无法生效、易用性差。

#### 1.21 历史遗留代码风格
- 证据：大量文件头 `# -*- coding: utf-8 -*-`、`@time`/`@file` 风格注释、`from functools import reduce`、
  `long` 兼容等（如 `SM2/_SM2.py`、`ecc/fq.py`、`backend/_backend.py`）。
- 影响：现代感差、可读性低。

#### 1.22 demo 目录风格混杂
- 证据：`pysmx/demo/` 含 11 个文件（demo1/demo2/cryptography 多套），重复且风格不一。
- 影响：新用户选择成本高。

---

## 2. 改进计划（路线图）

### 阶段一 — 安全修复（最高优先，建议本迭代完成）

目标：消除 Critical 级安全隐患，统一随机数实践。

- [ ] 新增 `pysmx/common/random.py`：提供基于 `secrets`/`os.urandom` 的 CSPRNG 工具
      （`random_hex(n)`、`random_bytes(n)`），替代 `random.choices`。
- [ ] 重写 `pysmx/SM2/_SM2.py`：
  - `get_random_str` 改用 CSPRNG（保持 hex 输出兼容既有调用）。
  - `Encrypt` 的临时值 `k`、 `generate_keypair` 的私钥 `d` 改走 CSPRNG；
    保留"调用方可显式传入熵"的兼容路径。
- [ ] 统一 `SM9`/`envelope` 的随机源到 `common/random.py`，消除重复。
- [ ] 收敛 `backend/_backend.py`：仅注册已实现的 `HashBackend`（及 SM3 HMAC backend），
      移除未实现的 `CipherBackend`/`HMACBackend` 注册。
- [ ] 验收：运行 `bandit -r pysmx` 无 High/Medium；`scripts/run_smx_tests.py` 全绿；
      补充 SM2 已知向量 + 私钥/临时值随机性单测。

### 阶段二 — 测试与代码质量

目标：提升覆盖与可维护性。

- [ ] 引入 `unittest discover` 自动发现，替换 `scripts/run_smx_tests.py` 手工登记；保留汇总输出。
- [ ] 补齐测试：`extra/envelope`、`ecc/*`、`ciphers/algorithm`、`crypto/hashlib`、
      `backend`、异常路径与边界值。
- [ ] 加入 CI 质量门禁：`ruff`（或 flake8）、`mypy`、`bandit`、覆盖率（coverage ≥ 目标值）。
- [ ] 清理：`ecc/fq.py` 裸 `except:` → `except NameError`；删除 py2 兼容壳与
      `modular_power` 冗余包装；处理 `SM4/_SM4.py:269` 空 `TODO`。
- [ ] 验收：lint/类型/安全扫描通过；覆盖率达标。

### 阶段三 — 工程化与打包

目标：现代化打包与清晰依赖。

- [ ] 迁移到 `pyproject.toml` 的 `[project]`（PEP 621），元数据从 `setup.py` 迁入；
      保留 `setup.py` 仅做兼容或删除。
- [ ] 修正版本声明：移除 `2.7`/`3.6`/`3.7`，添加 `python_requires=">=3.8"`。
- [ ] 拆分依赖：`requirements.txt`（运行时）、`requirements-test.txt`、`requirements-bench.txt`；
      利用 `extras_require`（test / bench）暴露给用户。
- [ ] CI 矩阵与声明版本对齐；benchmark 增加性能回归阈值断言（超阈值则 job 失败）。
- [ ] 清理工作区 `.pyc`，确认 `.gitignore` 覆盖充分。
- [ ] 验收：`python -m build` 出 sdist/wheel 可安装；CI 全矩阵绿。

### 阶段四 — 性能、API 与文档

目标：可用性、性能可选加速与文档完善。

- [ ] 性能（可选）：提供 Cython/C 加速后端（参考 `gmssl-pyx` 模式），benchmark 已具备对比基线；
      或在文档中明确"本库定位：学习/合规验证，生产高性能请使用 cryptography 绑定或 GmSSL"。
- [ ] 统一高层 API：在 `pysmx/` 顶层提供 facade（如 `sm2_encrypt/sm2_decrypt/...`），
      底层实现保持兼容；收敛 SM4 多套接口。
- [ ] 修正 `extra/__init__.py` 导出 `envelope`。
- [ ] 文档：补充安全模型与限制、CONTRIBUTING、SECURITY.md、推荐后端指引、更新 CHANGELOG；
      为公共 API 补全类型注解与 docstring。
- [ ] 精简 `demo/` 为统一示例集。
- [ ] 验收：文档齐全；可选加速后端可用且覆盖测试；公共 API 类型检查通过。

---

## 3. 风险与权衡

- **随机数替换**：会改变默认熵来源，需保留"调用方注入熵"的兼容路径，避免破坏现有签名接口。
- **C 扩展加速**：增加打包复杂度（需编译器/多平台 wheel），建议优先 Cython 并发布预编译 wheel；
  若资源有限，则以文档明确性能定位替代。
- **删除 py2 支持**：当前代码实际已 py3-only，影响极小，但需在 CHANGELOG 说明。
- **API 统一**：需保证向后兼容，建议以 facade 叠加而非破坏性改动现有函数。

---

## 4. 优先级速查

| 等级 | 项 | 关键文件 |
| --- | --- | --- |
| P0 | SM2 非安全随机（私钥/临时值） | `pysmx/SM2/_SM2.py:10,421,501` |
| P0 | hashlib 复刻冗余 | `pysmx/crypto/hashlib.py` |
| P1 | 裸 except / py2 残留 | `pysmx/ecc/fq.py:12-16` |
| P1 | backend 注册越界 | `pysmx/backend/_backend.py:31-33` |
| P2 | 测试覆盖缺口 | `pysmx/test/`、各未测模块 |
| P2 | 测试发现脆弱 | `scripts/run_smx_tests.py:13-19` |
| P3 | 纯 Python 性能 | `scripts/benchmark.py` 结果、各 `_*.py` |
| P4 | 版本声明矛盾 | `setup.py:58-68`、`.github/workflows/test.yml` |
| P4 | 缺 pyproject [project] | `pyproject.toml` |
| P4 | 依赖管理混乱 | `requirements.txt`、`test_requirements.txt` |
| P4 | CI 无质量门禁 | `.github/workflows/test.yml` |
| P5 | API 风格割裂 | `pysmx/SM2`、`SM3`、`SM4` |
| P5 | extra 未导出 | `pysmx/extra/__init__.py` |
| P5 | 文档缺口 | `doc/`、`README*` |
