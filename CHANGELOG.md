# 更新记录

## v1.1.0 (2026-09-29)

> 本版本包含自 1.0.0.post2 以来的全部累积差异。

### 性能优化

- **SM4 轮函数查表加速**：模块加载时预计算 4 张 256 项 T 表与轮密钥表，将每轮 `PUT/GET_UINT32_BE` + 4 次 Sbox 查表 + 4 次 `ROTL` 替换为 4 次查表 + 3 次异或；并去除 `deque`，改用 4 个局部变量累加器。轮密钥扩展同步使用预计算表
- **block_cyphers 链模式去重对象分配**：CBC/PCBC 移除每块的 `copy.deepcopy`，并统一改用 `XOR_BYTES`（返回 bytes）替代返回 list 的 `XOR`，消除 list↔bytes 往返
- **SM3 压缩函数直接移位**：`rotate_left`/`P_0`/`P_1` 及 `CF` 内部的旋转由 `divmod(BIT_EACH_32[n])` 改为直接移位；删除死代码 `CF2`/`CF3`/`__cf_reduce_*`
- **ZUC LFSR 环形缓冲**：LFSR 由 `list.append`+`pop(0)`（每拍 O(n)）改为 `deque(maxlen=16)`，移位降为 O(1)
- **SM2 点运算整数化**：`kG` 内部点运算由十六进制字符串解析/格式化改为整数元组表示，标量乘由 `bin(k)[3:]`+`reduce`+lambda 改为从 MSB 起的整型双加迭代，去除字符串解析开销；删除未使用的 `Inverse`
- **SM9 去除冗余转换**：KDF 直接透传 bytes（去掉 hex 往返），G1/G2 标量乘改用从高位起的位迭代，去除 `bits` 列表分配；`hmac` 提到模块顶部
- **密码学模块统一随机源与优化**：新增 `pysmx.common.random`（CSPRNG），SM2/SM9 复用全仓库统一随机源；收敛 `HashBackend` 注册逻辑
- **SM9 Fp12 固定窗口取幂**：`_fp12_pow` 由逐位平方-乘（乘法次数约 popcount）改为 w=4（十六进制分组）固定窗口取幂，预建 16 项表 `table[d]=a^d` 后按指数 hex 字符查表相乘，乘法次数降至约 n/4，benchmark 提速约 1.3x（base 相关表每次调用按传入的 `a` 重建，不全局缓存）
- **SM9 Miller 循环位展开改用 `bin()`**：`final_exp_bilinear` 中原 `while 移位收集 LSB + reverse` 的写法改为 `bin(N)[2:]` 直接生成 MSB-first 位序列，逻辑等价更简洁
- **SM4 CBC 链模式去冗余对象分配**：加密环直接用上一个密文块作下一轮 iv（去除每块 `bytes(output_data[i:i+16])` 重切片拷贝），输出由 `bytearray` 反复 `+=` 改为 `list` 收集末次 `b''.join`，去除冗余拷贝
- **SM4 流模式（SM4Stream）分块输出去冗余对象分配**：ECB/CBC/CFB/OFB/PCBC 全部 11 处分块循环的输出由 `bytearray` 反复 `+=` 改为 `list` 收集末次 `b''.join`，与块密码层 CBC 优化保持一致（轮函数 `one_round` 的字节拆分采用 `to_bytes` 写法）
- **SM4 ECB 分片统一**：ECB 各 16 字节块相互独立，流路径（``SM4Stream`` 的 ``_update_ecb`` / ``_encrypt_blocks_ecb`` / ``_decrypt_block_ecb``）改为与非流路径（``crypt_ecb`` 的 ``b''.join(map(one_round, 分片))``）一致的**内联分片**写法（分片 → 逐块 ``one_round`` → 一次性 ``join``），不引入额外的顶层函数。CBC/CFB/OFB/PCBC 为链式依赖（每块依赖上一块输出），不可分片，保持串行

### 新功能

- **SM2 用户标识（UID）签名支持**：`Sign` / `Verify` 新增 `uid` 参数。传入 `uid` 时按 GM/T 0003 的 `e = SM3(ZA || M)` 结构计算摘要，其中 `ZA = SM3(ENTL || IDA || a || b || xG || yG || xA || yA)` 由用户标识与签名方公钥导出；`uid` 缺省时保持原有行为（`E` 直接作为摘要），向后兼容。新增 `get_za(uid, PA, len_para)` 公开函数，便于外部独立计算 `ZA`。
- 新增 `pysmx/test/test_sm2_uid.py`：覆盖 `ZA` 已知答案、与 GmSSL 参考实现的签名/验签互操作、uid 差异、错误 uid/公钥/篡改消息等负向用例（GB/T 32918 标准向量，固定 `k` 可复现）。
- **统一 SM4 高层 API**：新增 `pysmx.sm4_encrypt` / `pysmx.sm4_decrypt`（支持 ECB/CBC/CFB/OFB/PCBC，无需记忆 `ENCRYPT`/`DECRYPT` 常量），收敛此前 `CryptSM4` / `SM4` / 裸函数多套接口并存的问题
- **性能对比基准测试工具**：新增 `scripts/benchmark.py` 与 CI 生成的 `doc/benchmark.md` 报告（pysmx vs gmssl）

### 接口变化

- `pysmx.SM2` 导出曲线参数 `sm2_N` / `sm2_G` 与公钥派生函数 `kG`
- `pysmx.SM2` 新增导出 `get_za`（用户标识哈希计算）
- `SM2EllipticCurvePrivateKey.sign(data, signature_algorithm, uid=None)` 与
  `SM2EllipticCurvePublicKey.verify(signature, data, signature_algorithm, uid=None)`
  同步支持 `uid`：`uid` 缺省时对 data 的摘要签名（保持原行为），传入 `uid` 时对原始消息
  M 按 `e = SM3(ZA || M)` 签名。GM/T 0003 的 ZA||M 结构仅基于 SM3，故传入非 SM3
  杂凑算法时会抛出 `ValueError`，而非静默降级
- `pysmx.extra` 顶层导出数字信封 API（`envelope_seal` / `envelope_open`）
- 版本号提升至 1.1.0

### 测试

- 新增 `pysmx/test/test_ecc.py`：补齐 `ecc` 模块（FQ/FQP 有限域与椭圆曲线运算）单测，填补 SM2/SM9 数学底座空白
- 新增 `pysmx/test/test_sm4_facade.py`：覆盖 SM4 统一 facade 各模式加解密回环与非法 mode
- 新增 `pysmx/test/test_sm2_random.py`：GB/T 32918 公钥派生向量（`kG(d)` 对齐标准 PX/PY）与私钥范围校验
- SM9 一致性测试整合至 `pysmx/test/test_sm9.py`

### 构建与依赖

- 拆分依赖清单：`requirements-test.txt` / `test_requirements.txt` / `requirements-bench.txt`
- 清理 `setup.py` 打包逻辑与 `pyproject.toml` 配置（PEP 621 元数据）
- **移除 astartool 依赖**：`pysmx/SM2/_cryptography.py` 对 `astartool.string.force_bytes` 的导入为冗余（从未调用），已从运行时与 `test` extra 依赖中移除

### 文档

- 重整文档版本目录：`doc/v1.0.0post1 → doc/v1.0.0`、`doc/v1.0.1 → doc/v1.1.0`
- API 文档新增统一随机源章节（7.2 CSPRNG）
- `pysmx/SM2/_SM2.py` 公开函数（`Sign`/`Verify`/`Encrypt`/`Decrypt`/`get_za`/`generate_keypair`）docstring 补全与口径统一：补齐缺失的 `len_para`/`Hexstr`/`encoding`/`hash_algorithm`/`mode`/`return` 参数说明，并将 `E`/`M` 统一描述为先消息后哈希（传 `uid` 时视为原始消息 `M`、`Hexstr=1` 视为十六进制串），与 `API_DOCS` 及 `Sign` 实现口径一致

### 杂项

- 脚本迁移至 `scripts/` 目录，并同步 `.github/workflows/test.yml`、`MANIFEST.in` 与文档引用
- 调整 `.gitignore` 忽略 demo 生成输出文件
- 相对导入整理；进一步将 `pysmx` 包内全部相对导入改为基于包名的绝对导入（`from pysmx.xxx import ...`），消除相对路径依赖

## v1.0.0.post2 (2026-07-18)

### 安全修复

- **SM2 随机数发生器升级为 CSPRNG**：修复私钥 / 临时值随机数可被预测导致的密钥泄露风险，符合 GM/T 0003 / GM/T 0009（随机值须落在 `[1, n-1]`）

### 文档

- 记录 SM2 随机数安全修复的改进计划（`doc/improvement_plan.md` 1.1 节）

### 构建

- 版本号提升至 1.0.0.post2

## v1.0.0.post1 (2026-07-13)

### Bug 修复

- **SM9 Ate 配对修正**：修正 BN 曲线上的 Ate 配对实现，使双线性配对校验、签名/验签、加密/解密与 KEM 之间自洽（GM/T 0044-2016）
- **SM9 KDF 修复**：修复 `_sm9_KDF`，以十六进制字符串向 SM3 `_BKDF` 传入密钥材料，避免非 UTF-8 字节触发 `UnicodeDecodeError`，并去除对未完成 SM3 bytes 版辅助函数的依赖
- **SM9 死代码清理**：删除 `_SM9.py` 中未使用的 `from pysmx.SM3 import KDF` 导入

### 测试

- **SM9 一致性测试整合**：将 SM9 一致性测试整合进 `pysmx/test/test_sm9.py`，覆盖双线性、签名/验签、加密/解密及 KEM 往返用例

### 构建 / 依赖

- **精简运行时依赖**：移除 `astartool>=0.1.0` 运行时依赖，`requirements.txt` 仅保留 `cryptography`

### 文档

- **版本与文档同步**：版本号升至 `1.0.0.post1`，API 文档迁移至 `doc/v1.0.0post1/`（中英文同步）

## v1.0.0 (2026-07-10)

### 新增功能

- **SM9 标识密码算法完整实现**：基于 BN 曲线的双线性配对，支持签名验签、加解密、密钥封装(KEM)
- **数字信封 (GM/T 0010-2012)**：SM2 非对称加密 + SM4-CBC 对称加密组合，提供 `envelope_seal`/`envelope_open` 便捷接口
- **Cryptography Hazmat 兼容层**：SM2/SM3/SM4/SM9/ZUC 全部支持 Python `cryptography` 库的 `hashes.Hash`、`ciphers.Cipher` 等底层原语接口
- **ECC 椭圆曲线模块**：`pysmx/ecc/` 实现 BN 曲线、扩域运算、Ate 配对
- **填充工具**：支持 PKCS5/PKCS7/Zero/ISO10126/NoPadding 五种填充方案
- **分组密码抽象层**：`pysmx/block_cyphers/` 统一分组密码操作接口
- **SM4 流式加解密**：`SM4Stream` 支持 `update()`/`finalize()` 增量处理接口，适用于大文件/流式数据。支持全部 5 种模式（ECB/CBC/CFB/OFB/PCBC）
- **SM4 流式密码 cryptography 封装**：`SM4StreamCipher` 在 cryptography 兼容层暴露流式接口，与 `SM4Stream` 功能等同
- **完整测试套件**：覆盖 SM2/SM3/SM4/SM9/ZUC/填充 的单元测试，含 SM4 流式（27 项）和 block_cyphers 回归（12 项）

### 接口变化

- **SM4 cryptography 后端切换为 pysmx 原生实现**：`SM4Algorithm` 不再依赖 cryptography 内置 SM4，改为封装 pysmx `Sm4` 类。`SM4Algorithm` 作为 `BlockCipherAlgorithm` 描述符，`SM4ModePCBC` 作为自定义模式。新增 `sm4_encrypt_xxx`/`sm4_decrypt_xxx` 共 10 个便捷函数（ECB/CBC/CFB/OFB/PCBC），从 `pysmx.ciphers.algorithm` 统一导出，`pysmx.SM4._cryptography` 改为 re-export。
- SM4 模块重构，API 保持不变
- SM2 模块新增 `_cryptography.py` 兼容接口
- SM3 模块新增后端抽象（`_backend.py`）
- 版本号从 0.3.2-alpha.1 升级至 1.0.0

### 安全修复

- **SM2 随机数发生器升级为 CSPRNG**：私钥 `d` 与加密临时值 `k` 原先由 `random.choices`（Mersenne Twister，可预测 PRNG）生成，存在私钥被反推、明文乃至私钥泄露风险。现已改用 `secrets`（密码学安全随机数发生器），并将取值约束到 `[1, sm2_N-1]`，符合 GM/T 0003 / GM/T 0009 要求。`is_prime` 的 Miller-Rabin 基数随机源同步改为 `secrets`。

### Bug 修复

- **SM4 CFB/OFB/PCBC 解密路径**：修复 `block_cyphers` 中 bytearray 与 bytes 拼接导致的 TypeError（CFB/OFB/PCBC 模式下解密返回 bytearray，onx_round 返回 bytes，拼接抛出 TypeError）

