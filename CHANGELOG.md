# 更新记录

## v1.0.1 (2026-07-12)

### 性能优化

- **SM4 轮函数查表加速**：模块加载时预计算 4 张 256 项 T 表与轮密钥表，将每轮 `PUT/GET_UINT32_BE` + 4 次 Sbox 查表 + 4 次 `ROTL` 替换为 4 次查表 + 3 次异或；并去除 `deque`，改用 4 个局部变量累加器。轮密钥扩展同步使用预计算表
- **block_cyphers 链模式去重对象分配**：CBC/PCBC 移除每块的 `copy.deepcopy`，并统一改用 `XOR_BYTES`（返回 bytes）替代返回 list 的 `XOR`，消除 list↔bytes 往返
- **SM3 压缩函数直接移位**：`rotate_left`/`P_0`/`P_1` 及 `CF` 内部的旋转由 `divmod(BIT_EACH_32[n])` 改为直接移位；删除死代码 `CF2`/`CF3`/`__cf_reduce_*`
- **ZUC LFSR 环形缓冲**：LFSR 由 `list.append`+`pop(0)`（每拍 O(n)）改为 `deque(maxlen=16)`，移位降为 O(1)
- **SM2 点运算整数化**：`kG` 内部点运算由十六进制字符串解析/格式化改为整数元组表示，标量乘由 `bin(k)[3:]`+`reduce`+lambda 改为从 MSB 起的整型双加迭代，去除字符串解析开销；删除未使用的 `Inverse`
- **SM9 去除冗余转换**：KDF 直接透传 bytes（去掉 hex 往返），G1/G2 标量乘改用从高位起的位迭代，去除 `bits` 列表分配；`hmac` 提到模块顶部

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

