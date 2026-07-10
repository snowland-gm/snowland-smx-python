# 更新记录

## v1.0.0 (2026-07-10)

### 新增功能

- **SM9 标识密码算法完整实现**：基于 BN 曲线的双线性配对，支持签名验签、加解密、密钥封装(KEM)
- **数字信封 (GM/T 0010-2012)**：SM2 非对称加密 + SM4-CBC 对称加密组合，提供 `envelope_seal`/`envelope_open` 便捷接口
- **Cryptography Hazmat 兼容层**：SM2/SM3/SM4/SM9/ZUC 全部支持 Python `cryptography` 库的 `hashes.Hash`、`ciphers.Cipher` 等底层原语接口
- **ECC 椭圆曲线模块**：`pysmx/ecc/` 实现 BN 曲线、扩域运算、Ate 配对
- **填充工具**：支持 PKCS5/PKCS7/Zero/ISO10126/NoPadding 五种填充方案
- **分组密码抽象层**：`pysmx/block_cyphers/` 统一分组密码操作接口
- **完整测试套件**：覆盖 SM2/SM3/SM4/SM9/ZUC/填充 的单元测试

### 接口变化

- SM4 模块重构，API 保持不变
- SM2 模块新增 `_cryptography.py` 兼容接口
- SM3 模块新增后端抽象（`_backend.py`）
- 版本号从 0.3.2-alpha.1 升级至 1.0.0

