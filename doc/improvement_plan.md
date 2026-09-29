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
- 状态：✅ 已修复（已提交，v1.1.0）。
  - 新增统一随机源 `pysmx/common/random.py`，提供 `random_bytes(n)` / `random_int(upper)`
    / `random_hex(n)`，全部基于 `secrets` / `os.urandom`，作为全包的单一随机来源。
  - `pysmx/SM2/_SM2.py` 的 `get_random_str` 改用 `random_int`（约束到 `[1, sm2_N-1]`，
    符合 GM/T 0003）；`Encrypt` 临时值 `k`（line 409）与 `generate_keypair` 私钥 `d`
    （line 489）均改走该 CSPRNG；移除 `random` 导入与无用 `letterlist`。
  - `is_prime` 的 Miller-Rabin 基数改用 `secrets`。
  - 新增回归测试（`test_random_source_secure_range` / `test_random_source_not_constant` /
    `test_keypair_private_key_in_range`），全量测试通过。

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
- 证据（历史）：`scripts/run_smx_tests.py` 曾手工逐个 import 测试类；新增测试文件若未登记则不会运行。
- 影响：CI 仅运行被手工登记的用例，新测试易被遗漏。
- 状态：✅ 已修复（已提交，v1.1.0）。`scripts/run_smx_tests.py` 改为基于
  `unittest.TestLoader().discover(start_dir='pysmx/test', pattern='test_*.py')` 自动发现，
  新增 `test_*.py` 即自动纳入，无需手工登记。

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
- 证据（历史）：
  - `requirements.txt` 曾含 `cryptography` 与 `astartool` 两个运行时依赖。
  - `test_requirements.txt`：`gmssl`（benchmark 可选基线)。`astartool` 曾是 test 依赖。
- 状态：✅ 已修复（已提交，v1.1.0）。
  - `astartool` 对 `pysmx/SM2/_cryptography.py` 的 `force_bytes` 导入为冗余（从未调用），已删除该导入；
    并从 `requirements.txt`、`requirements-test.txt`、`test_requirements.txt`、
    `pyproject.toml` 的 `[test]` extra 移除 `astartool`。
  - 运行时依赖收敛为 `cryptography` 一项。
- 影响（残余）：测试/基准依赖虽已拆分文件，但 `extras_require` 仍仅暴露 `test`，
  `bench` extra 未接 `requirements-bench.txt`；可进一步在 `pyproject.toml` 显式声明。

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
- SM4：`Sm4().crypt_ecb`（面向对象）与 `sm4_encrypt_ecb`（函数式，来自 crypto 后端）并存；
  另已新增顶层 facade `sm4_encrypt(mode, key, data, iv=None)` /
  `sm4_decrypt(mode, key, data, iv=None)`（见 1.17 状态），统一 ECB/CBC/CFB/OFB/PCBC。
- 缺少统一高层 API（如 `sm2_encrypt(pk, msg)` 风格），调用方式割裂。
- 状态：🔶 部分修复（已提交，v1.1.0）。`pysmx/__init__.py` 新增 SM4 高层 facade
  （`sm4_encrypt`/`sm4_decrypt`，内部按 mode 委派 `sm4_crypt_*`）；`pysmx/SM2/__init__.py`
  补全导出 `sm2_N`、`sm2_G`、`kG`（便于外部做 `kG(d, sm2_G)` 等运算）。SM2 的
  `Encrypt/Decrypt/Sign/Verify` 仍保持原有 camelCase 低层接口，未做破坏性统一。

#### 1.18 子模块导出不完整
- 证据：`pysmx/extra/__init__.py` 为空，`envelope` 未被导出，需深层 import
  （`from pysmx.extra.envelope import ...`）。
- 状态：⬜ 未修复（可在阶段四处理）。

#### 1.19 文档缺口
- 现有：`README.md`/`README.en.md`、`doc/v1.0.0post1`、`doc/v1.0.0post2`、`doc/v1.1.0`
  （API 文档）、`doc/benchmark.md`、`CHANGELOG.md`。
- 缺失：
  - 安全模型与限制说明（尤其性能定位）。SM2 随机数风险已随 P0 修复消除。
  - 贡献指南（CONTRIBUTING）、安全漏洞上报（SECURITY.md）。
  - "推荐后端"指引（何时用 `_SM2` 纯 Python vs `_cryptography` 绑定）。
- 状态：🔶 部分修复。`__version__` 已更新为 `1.1.0`，`CHANGELOG.md` 已补齐
  `v1.0.0.post2` 与 `v1.1.0` 段落，并删除未实际发版的 `v1.0.1`。API 文档随版本新增
  `doc/v1.0.0post2`、`doc/v1.1.0`。

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

#### 1.23 `_autorange` 迭代次数不递增，基准数据不可信
> 归属：**P3 — 性能**（前置阻塞项，应先于任何性能优化结论）

- 证据：`scripts/benchmark.py:97-106` 的 `while True` 循环内缺少 `n *= 2`
  （标准库 `timeit` 中为 `n <<= 1`），`n` 恒为 1。
- 影响：
  - 单次耗时 **< 0.1 s** 的操作 → `dt` 永远达不到 `target`，`n` 也永远到不了
    `max_iters` → **死循环**（脚本启动即挂死，只能 Ctrl-C）。
  - 单次耗时 **≥ 0.1 s** 的操作 → 以**单次采样**作为结果，噪声极大。
  - 直接体现为 `doc/benchmark.md` 的自相矛盾：SM3 哈希 64 B 为 1.9 ops/s（≈526 ms/次），
    而 1 KB 反而是 3.1 ops/s（≈322 ms/次）——数据量涨 16 倍、耗时反降 40%，物理上不可能。
- 影响（延伸）：现有基准数据无法用于判断任何优化（含并行化）是否划算，
  必须修好并**重跑基线**后再做决策。
- 状态：⬜ 未处理。

#### 1.24 缺少批处理 / 向量化优化
> 归属：**P3 — 性能**（单线程、零 IPC 开销、对所有调用方自动生效，性价比最高）

- 证据：
  - `pysmx/block_cyphers/_block_cyphers.py:104` —— CBC 解密用
    `b''.join(map(XOR_BYTES, tmp, ivs[:-1]))`，逐块 lambda + 逐字节 `map`，
    未使用大整数 XOR。
  - `pysmx/SM4/_SM4.py` —— `one_round` 每块付一次 `struct.unpack_from` / `struct.pack`，
    32 轮循环未外提、未批量推进多块。
  - `pysmx/SM2/_SM2.py:332-342` —— `Verify` 做了**两次完整标量乘 + 一次点加 +
    一次额外模逆**（`_jac_to_affine` 中的 `pow(Z, P-2, P)`），未用 Shamir's trick
    （interleaved 多标量乘）合并为一次 `[s]G + [t]P`。
  - `pysmx/ZUC/_ZUC.py:85,156` —— `zuc_generate_keystream` 一次仅产出
    `buffer_size=100` 个字，`zuc_encrypt` 走生成器 `next(self)` 逐字吐出。
  - 无 G 点窗口预计算表（w=4/5 NAF）。
- 影响：解释器 per-op 开销未被摊销；ZUC 的 per-word 生成器开销可能超过计算本身；
  XOR 段慢一个数量级。
- 预期收益：整体 3–5x（大整数 XOR 十倍级、Shamir's trick 1.5–1.9x、
  循环外提 1.3–2x、G 窗口预计算 1.3–2x），**零 API 变更**。
- 状态：⬜ 未处理。

#### 1.25 无批量并行路径（进程级）
> 归属：**P3 — 性能**

- 现状：全库同步单线程。SM2 单次标量乘 100–400 ms、SM9 单次验签 0.5–2 s，
  批量场景只能串行；而进程池一次任务往返仅 0.1–1 ms，开销占比 < 1%。
- 各算法可并行性结论（已逐一核对依赖链）：
  - **SM4**：ECB 加/解密可并行；CBC/CFB **仅解密可并行**（密文全部已知）；
    OFB（`O_i = E(O_{i-1})`）与 PCBC（双向链式）加解密均串行。
  - **SM3**：单条消息为 Merkle–Damgård 严格链式 `V_{i+1} = CF(V_i, B_i)`
    （`pysmx/SM3/_SM3.py:206-207`），**不可并行**；仅"批量多消息"可并行，
    且单条仅约 0.2 ms，需打包数千条为一个 task 才划算。
  - **SM2**：`kG` 为 double-and-add 256 次串行迭代（`pysmx/SM2/_SM2.py:141-150`），
    单次标量乘不可并行；但**批量验签 / 签名 / 密钥生成 / 数字信封是最理想的并行任务**。
  - **SM9**：Miller 循环（64 次迭代）与 `final_exponentiate`（约 3000 位指数，走内置
    `pow`）内部不可并行；**批量验签 / 解封装收益极为确定**。
  - **ZUC**：LFSR 状态严格递推，**加解密均不可并行，不建议并行化**（应做 1.24 的
    串行优化）。
- 状态：⬜ 未处理。建议 opt-in 新增 `pysmx/parallel/`，仅覆盖批量场景，
  内置阈值回退（数据量 < 1 MB 或任务数过少时走串行）、`max_workers=1` 强制串行开关、
  结果保序；只用 `concurrent.futures` / `multiprocessing`，零新增依赖。
- **判断标准**：并行能否做，取决于"并行后的产物是否与标准实现**逐字节一致**"。
  一致 → 属标准内的合法并行（ECB、CBC 解密、CFB 解密、CTR）；不一致 → 等于自造了
  一种新算法，产物无法被第三方验证，与国密合规定位冲突。
- **明确不做**（以下为**性能优化手段的取舍**，非功能缺口；三者都会改变标准输出字节）：
  - **树哈希 SM3** —— GM/T 0004 定义的是标准 Merkle–Damgård，**未定义任何树模式**，
    分块大小 / 层数 / 域分离等参数一旦自造即为私有变体，算出的不再是 SM3 摘要。
    更严重的是 SM2 的 `ZA = SM3(ENTL||ID||a||b||xG||yG||xA||yA)` 与 `e = SM3(ZA||M)`、
    `KDF`、SM9 的 H1/H2 均依赖 SM3 —— 改动会连带使**签名/验签/封装全线失配**。
    （对比：BLAKE3 的并行合法，是因为树参数被写进了标准本身。）
  - **分段 CBC（加密）** —— 把明文切成 N 段、每段配独立 IV 各自成链再拼接。两个问题：
    ① **格式**：产物已非标准 CBC 密文（GM/T 0002 / GB/T 32907 未定义任何分段格式），
    接收方须额外知道段数、边界与 IV 派生规则，GmSSL / OpenSSL / UKey / 对端服务均无法解密；
    ② **安全**：跨块链式绑定被切断——标准 CBC 中改动任一块会污染其后所有块的解密，
    分段后篡改 / 替换 / 重排只影响本段，可检测性下降；若 IV 复用或可预测（如按段号派生），
    则进一步退化为 ECB 式的明文块相等性泄露。
  - **ZUC 多 IV 密钥流切分** —— LFSR 状态严格递推，为不同 IV 分段生成密钥流属于
    自定义非标准协议。
- 注 1：**"单条消息的块级并行"不可行，不等于"CBC 加密与并行无缘"**。同时加密**多条
  独立消息**（各带独立 IV / 密钥）属天然的批量并行任务，与标准完全兼容，归入上述
  "批量场景"即可。同理，ECB 的块级并行、CBC/CFB 解密的块级并行也都成立。
- 注 2：**须区分"性能优化取舍"与"功能缺失"**。本节"不做"仅指**不采用这些性能优化手段**
  —— 它们以改变标准算法语义为代价换取并行度，故不采纳；**这不是功能缺口**。
  反之，"CTR 模式尚未实现"属功能 / API 覆盖范畴（`pysmx/block_cyphers/_block_cyphers.py`
  仅 ecb/cbc/pcbc/ofb/cfb，`pysmx/SM4/_SM4.py:269` 的 "ECB/CBC/CTR/..." 为待办空 TODO），
  与本节的取舍无关：一旦按标准实现 CTR，其块级并行（`S_i = E_K(nonce||counter_i)`
  各块独立、并行与串行结果逐字节一致）即属标准内合法并行，是"单条大消息加密也要并行"
  的正确路径——而不是去改造 CBC。

#### 1.26 缺少异步（asyncio）接口
> 归属：**P5 — API 设计与文档**

- 证据：无任何 `async` 接口；在 FastAPI / aiohttp / gRPC 中同步调用 `Verify`
  （单次可达数百 ms）会阻塞整个 event loop，所有并发请求一起停摆。
- 定位说明（避免误用）：协程在纯 CPU 场景下**不具备加速价值**——
  一次 `await` 切换约 0.5–2 μs，比普通函数调用贵 10–40 倍；在 SM4 轮函数、
  SM3 压缩函数、SM2 点运算、ZUC LFSR 等热点内部引入协程是**灾难性负优化**。
  协程仅承担编排职责：不阻塞 event loop、`Semaphore` 背压、I/O 与 CPU 重叠
  （当前 CPU 为绝对瓶颈，I/O 占比 < 1%，重叠收益接近零——**先快起来，再谈流水线**）。
- 状态：⬜ 未处理（低优先，若当前无 asyncio 使用方可无限期延后）。
  建议新增 `pysmx/aio/` 异步门面，内部以 `loop.run_in_executor` 复用 1.25 的进程池
  （3.8 无 `asyncio.to_thread`），**协程本身不承载计算**。

#### 1.27 `Sm4` 实例可变状态导致非重入（并行化阻塞项）
> 归属：**P1 — 正确性与健壮性**

- 证据：`pysmx/block_cyphers/_block_cyphers.py` 的 `crypt_ofb` / `crypt_cfb`
  解密分支会临时修改 `self.mode` 并执行 `self.sk = self.sk[::-1]`。
- 影响：方法非重入、实例非并发安全；任何实例复用或并行化都会踩雷。
- 状态：⬜ 未处理。并行化（1.25）前必须先消除"临时改实例状态"，改为局部变量传参。

---

## 2. 改进计划（路线图）

### 阶段一 — 安全修复（最高优先，建议本迭代完成）

目标：消除 Critical 级安全隐患，统一随机数实践。

- [x] 新增 `pysmx/common/random.py`：提供基于 `secrets`/`os.urandom` 的 CSPRNG 工具
      （`random_hex(n)`、`random_bytes(n)`、`random_int(upper)`），替代 `random.choices`。
- [x] 重写 `pysmx/SM2/_SM2.py`：
  - `get_random_str` 改用 CSPRNG（保持 hex 输出兼容既有调用）。
  - `Encrypt` 的临时值 `k`、 `generate_keypair` 的私钥 `d` 改走 CSPRNG；
    保留"调用方可显式传入熵"的兼容路径。
- [ ] 统一 `SM9`/`envelope` 的随机源到 `common/random.py`，消除重复。
- [ ] 收敛 `backend/_backend.py`：仅注册已实现的 `HashBackend`（及 SM3 HMAC backend），
      移除未实现的 `CipherBackend`/`HMACBackend` 注册。
- [x] 验收：运行 `scripts/run_smx_tests.py` 全绿（全量测试通过）；
      补充 SM2 随机数范围/非恒定/私钥范围单测（向量与随机性）。`bandit` 扫描门禁尚未接入 CI。

### 阶段二 — 测试与代码质量

目标：提升覆盖与可维护性。

- [x] 引入 `unittest discover` 自动发现，替换 `scripts/run_smx_tests.py` 手工登记；保留汇总输出。
- [x] 补齐部分测试：新增 `ecc/*` 基础单测（`test_ecc.py`：FQ/FQ2/FQ12/EC）、
      SM4 高层 facade 单测（`test_sm4_facade.py`）、SM2 国标公钥派生向量
      （`test_sm2_random.py`）。`extra/envelope`、`ciphers/algorithm`、`crypto/hashlib`、
      `backend` 仍缺独立单测。
- [ ] 加入 CI 质量门禁：`ruff`（或 flake8）、`mypy`、`bandit`、覆盖率（coverage ≥ 目标值）。
- [ ] 清理：`ecc/fq.py` 裸 `except:` → `except NameError`；删除 py2 兼容壳与
      `modular_power` 冗余包装；处理 `SM4/_SM4.py:269` 空 `TODO`。
- [ ] 消除 `Sm4` 的临时实例状态修改（`crypt_ofb` / `crypt_cfb` 解密分支改动
      `self.mode` 并反转 `self.sk`），改为局部变量传参，使方法可重入、实例可并发复用
      （1.27，为 1.25 的并行化前置）。
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
- [x] 统一高层 API（部分）：在 `pysmx/` 顶层新增 SM4 facade（`sm4_encrypt`/`sm4_decrypt`），
      底层实现保持兼容；SM2 补全导出 `sm2_N`/`sm2_G`/`kG`。SM2 的 `Encrypt/Decrypt/Sign/Verify`
      仍保留 camelCase 低层接口，未做破坏性统一。
- [ ] 修正 `extra/__init__.py` 导出 `envelope`。
- [x] 文档：更新 CHANGELOG（`v1.0.0.post2`/`v1.1.0`，删除未发版的 `v1.0.1`）；新增 API 文档
      `doc/v1.0.0post2`、`doc/v1.1.0`；`__version__` 升至 `1.1.0`。
      仍需补充：安全模型与限制、CONTRIBUTING、SECURITY.md、推荐后端指引。
- [ ] 精简 `demo/` 为统一示例集。
- [ ] **（前置）修正 `scripts/benchmark.py:97-106` 的 `_autorange`**：`n` 按
      1,2,5,10,20,50… 递增（或直接改用 `timeit.Timer.autorange`），重跑基准拿到可信基线；
      CI 增加性能回归阈值断言。在此之前任何"加速比"结论都不可信。
- [ ] **串行 / 批处理优化（优先于并行）**：SM2 `Verify` 双标量乘改 Shamir's trick
      （`_SM2.py:332-342`）；CBC/CFB XOR 段改大整数 XOR（`_block_cyphers.py:104`）；
      SM4 32 轮循环外提 + 批量推进；ZUC 去掉逐字生成器路径（`_ZUC.py:156`）；
      G 点窗口预计算表。目标 3–5x，零 API 变更。
- [ ] **并行执行层（opt-in）**：新增 `pysmx/parallel/`，仅覆盖批量场景——SM2 批量
      验签 / 签名 / 密钥生成、SM9 批量验签、SM4-ECB 与 CBC 解密的大数据分片；
      内置阈值回退与 `max_workers=1` 串行开关，结果保序。
- [ ] **异步门面（低优先，按需）**：新增 `pysmx/aio/`，以 `loop.run_in_executor` 复用
      进程池（3.8 无 `asyncio.to_thread`），协程只做编排、不承载计算。
- [ ] 明确**不做（性能优化手段，非功能缺口）**：树哈希 SM3、分段 CBC（加密）、
      ZUC 多 IV 密钥流切分——三者均以改变标准算法输出字节为代价换取并行度，
      产物无法被第三方验证，与国密合规定位冲突（理由见 1.25）。
      注意此处的"不做"指**不采用这些加速方案**，不等于模式/功能缺失；
      CTR 模式尚未实现属功能覆盖范畴，与本节取舍无关。
- [ ] 验收：文档齐全；可选加速后端可用且覆盖测试；公共 API 类型检查通过；
      并行路径实测并行 vs 串行 wall time，以数字确定启用阈值。

---

## 3. 风险与权衡

- **随机数替换**：会改变默认熵来源，需保留"调用方注入熵"的兼容路径，避免破坏现有签名接口。
- **C 扩展加速**：增加打包复杂度（需编译器/多平台 wheel），建议优先 Cython 并发布预编译 wheel；
  若资源有限，则以文档明确性能定位替代。
- **删除 py2 支持**：当前代码实际已 py3-only，影响极小，但需在 CHANGELOG 说明。
- **API 统一**：需保证向后兼容，建议以 facade 叠加而非破坏性改动现有函数。
- **进程并行（1.25）**：Windows 默认 `spawn`，且 `pysmx/block_cyphers/_block_cyphers.py:10`、
  `pysmx/SM4/_SM4.py:19` 顶层加载 OpenSSL，每个 worker 启动需 100–300 ms → **必须使用
  长期复用的进程池，绝不每次调用新建**；worker 模块应尽量只 import 纯 Python 部分
  （`pysmx/SM2/_SM2.py:9-13` 不依赖 `cryptography`，是干净范例）。任务需 picklable，
  现有 `map(lambda ...)` 写法须改为模块顶层函数。CI runner 仅 2 核，并行项可能测出
  加速比 < 1，故 **CI 只做正确性校验、不做性能断言**，加速比需标注核数。
- **协程误用（1.26）**：协程切换比函数调用贵 10–40 倍，在热点循环内部 `await` 是负优化；
  协程只能放在最外层的任务调度边界，CPU 计算一律交给 executor。另注意 3.8 无
  `asyncio.to_thread`（3.9+）、无 `asyncio.TaskGroup` / `asyncio.timeout`（3.11+）。
- **算法语义变更（性能优化取舍）**：树哈希 SM3、分段 CBC（加密）、ZUC 多 IV 密钥流切分
  会改变标准算法输出，产物无法被第三方验证，故**不将其作为加速手段采纳**。
- **并行的判定线**：产物是否与标准实现**逐字节一致**。一致即属标准内合法并行
  （ECB、CBC 解密、CFB 解密、CTR）；不一致则等于自造新算法。其中树哈希 SM3 还会
  连带破坏 SM2 的 `ZA` / `e` 与 `KDF`、SM9 的 H1/H2，使签名验签全线失配。
- **性能优化取舍 ≠ 功能缺失**：上述"不做"仅关涉性能优化路径；"某模式未实现"（如 CTR）
  属功能 / API 覆盖问题，应另立条目跟踪，不可混为同一类，否则会把"不该做的加速方案"
  误登记成"待补的功能缺口"。

---

## 4. 优先级速查

| 等级 | 项 | 关键文件 | 实现现状 |
| --- | --- | --- | --- |
| P0 | SM2 非安全随机（私钥/临时值） | `pysmx/SM2/_SM2.py` | ✅ 已修复（统一 CSPRNG，v1.1.0） |
| P0 | hashlib 复刻冗余 | `pysmx/crypto/hashlib.py` | ⬜ 未处理 |
| P1 | 裸 except / py2 残留 | `pysmx/ecc/fq.py:12-16` | ⬜ 未处理 |
| P1 | backend 注册越界 | `pysmx/backend/_backend.py:31-33` | ⬜ 未处理 |
| P1 | `Sm4` 实例状态非重入 | `pysmx/block_cyphers/_block_cyphers.py` | ⬜ 未处理（1.27，并行化阻塞项） |
| P2 | 测试覆盖缺口 | `pysmx/test/`、各未测模块 | 🔶 部分补齐（ecc/SM4 facade/SM2 向量） |
| P2 | 测试发现脆弱 | `scripts/run_smx_tests.py` | ✅ 已改为 discover 自动发现（v1.1.0） |
| P3 | 纯 Python 性能 | `scripts/benchmark.py` 结果、各 `_*.py` | ⬜ 未处理（可选 Cython 加速） |
| P3 | 基准计时缺陷 `_autorange` | `scripts/benchmark.py:97-106` | ⬜ 未处理（1.23，阻塞所有性能结论） |
| P3 | 缺批处理 / 向量化优化 | `_block_cyphers.py:104`、`_SM4.py`、`_SM2.py:332-342`、`_ZUC.py:85,156` | ⬜ 未处理（1.24，预期 3–5x） |
| P3 | 无批量并行路径 | 新增 `pysmx/parallel/` | ⬜ 未处理（1.25，仅批量场景可行） |
| P4 | 版本声明矛盾 | `setup.py:58-68`、`.github/workflows/test.yml` | ⬜ 未处理 |
| P4 | 缺 pyproject [project] | `pyproject.toml` | ⬜ 未处理 |
| P4 | 依赖管理混乱 | `requirements*.txt` | ✅ astartool 已移除（v1.1.0） |
| P4 | CI 无质量门禁 | `.github/workflows/test.yml` | ⬜ 未处理（ruff/mypy/bandit/coverage） |
| P5 | API 风格割裂 | `pysmx/SM2`、`SM3`、`SM4` | 🔶 部分统一（SM4 facade + SM2 导出，v1.1.0） |
| P5 | extra 未导出 | `pysmx/extra/__init__.py` | ⬜ 未处理 |
| P5 | 文档缺口 | `doc/`、`README*` | 🔶 部分补齐（CHANGELOG v1.1.0 + API 文档） |
| P5 | 缺异步（asyncio）接口 | 新增 `pysmx/aio/` | ⬜ 未处理（1.26，低优先，仅编排价值） |

> 图例：✅ 已修复并随 v1.1.0 提交；🔶 部分修复；⬜ 未处理。当前版本 `__version__ = "1.1.0"`。
> 编号说明：1.23–1.27 为后补条目，为避免打乱既有编号，统一接续于 1.22 之后，
> 各条以"归属"标注其优先级归属段（P1 / P3 / P5）。
