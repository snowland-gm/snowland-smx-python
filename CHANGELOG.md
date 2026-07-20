# 更新记录

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

