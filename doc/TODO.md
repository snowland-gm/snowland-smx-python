# snowland-smx-python 待办清单（TODO）

> 基于 `doc/improvement_plan.md` 的仓库级不足分析与改进路线图提炼而成。
> 按阶段与优先级排列，可逐项勾选推进。详细背景与证据见 `doc/improvement_plan.md`。

---

## 阶段一 — 安全修复（P0，最高优先）

- [x] 新增 `pysmx/common/random.py`：基于 `secrets` / `os.urandom` 的 CSPRNG 工具（`random_hex` / `random_bytes` / `random_int`）
- [x] 重写 `pysmx/SM2/_SM2.py` 的 `get_random_str`，改用 CSPRNG（保持 hex 输出兼容既有调用）
- [x] `Encrypt` 的临时值 `k` 与 `generate_keypair` 的私钥 `d` 改走 CSPRNG，保留"调用方注入熵"的兼容路径 — `pysmx/SM2/_SM2.py:421,501`
- [x] 统一 `SM9` / `envelope` 的随机源到 `common/random.py` — `pysmx/SM9/_SM9.py`、`pysmx/extra/envelope.py`
- [x] 收敛 `pysmx/backend/_backend.py`：仅注册已实现的 `HashBackend`，移除未实现的 `CipherBackend` / `HMACBackend` 注册 — `pysmx/backend/_backend.py`
- [ ] 验收：`bandit -r pysmx` 无 High/Medium；`scripts/run_smx_tests.py` 全绿；补充 SM2 随机性 / 已知向量单测

## 阶段二 — 测试与代码质量（P1 / P2）

- [x] 引入 `unittest discover` 自动发现，替换 `scripts/run_smx_tests.py` 手工登记用例 — `scripts/run_smx_tests.py`
- [ ] 补齐测试：`extra/envelope`、`ecc/*`、`ciphers/algorithm`、`crypto/hashlib`、`backend`、异常路径与边界值 — `pysmx/test/`
- [ ] CI 加入质量门禁：`ruff`（或 flake8）、`mypy`、`bandit`、覆盖率（coverage）— `.github/workflows/test.yml`
- [x] 修复 `pysmx/ecc/fq.py` 裸 `except:` → 移除 py2 兼容壳，类型改用 `int` — `pysmx/ecc/fq.py`
- [x] 清理 `SM4/_SM4.py:269` 空 `TODO`；删除 `modular_power` 冗余递归包装（直接 `pow`）— `pysmx/SM2/_SM2.py`
- [ ] 验收：lint / 类型 / 安全扫描通过；覆盖率达标

## 阶段三 — 工程化与打包（P4）

- [x] 迁移到 `pyproject.toml` 的 `[project]`（PEP 621），元数据从 `setup.py` 迁出
- [x] 修正版本声明：移除 `2.7` / `3.6` / `3.7`，添加 `python_requires=">=3.8"` — `pyproject.toml`
- [x] 拆分依赖：`requirements.txt`（运行时）/ `requirements-test.txt` / `requirements-bench.txt`，完善 `extras_require` — `pyproject.toml`
- [ ] CI 矩阵与声明版本对齐；benchmark 增加性能回归阈值断言
- [ ] 清理工作区 `.pyc`，确认 `.gitignore` 覆盖充分
- [ ] 验收：`python -m build` 出 sdist/wheel 可安装；CI 全矩阵绿

## 阶段四 — 性能、API 与文档（P3 / P5）

- [ ] 提供 Cython / C 加速后端（参考 `gmssl-pyx` 模式）；或在文档中明确性能定位 — `scripts/benchmark.py`
- [ ] 顶层 facade 统一高层 API（如 `sm2_encrypt` 等），收敛 SM4 多套接口
- [x] 修正 `pysmx/extra/__init__.py` 导出 `envelope`
- [ ] 文档：安全模型与限制说明、CONTRIBUTING、SECURITY.md、推荐后端指引、更新 CHANGELOG
- [ ] 公共 API 补全类型注解与 docstring
- [ ] 精简 `pysmx/demo/` 为统一示例集
- [ ] 验收：文档齐全；可选加速后端可用并覆盖测试；公共 API 类型检查通过

---

## 优先级速查

| 等级 | 项 | 关键文件 | 状态 |
| --- | --- | --- | --- |
| P0 | SM2 非安全随机（私钥 / 临时值） | `pysmx/SM2/_SM2.py` | ✅ |
| P0 | hashlib 复刻冗余 | `pysmx/crypto/hashlib.py` | 待处理 |
| P1 | 裸 except / py2 残留 | `pysmx/ecc/fq.py` | ✅ |
| P1 | backend 注册越界 | `pysmx/backend/_backend.py` | ✅ |
| P2 | 测试覆盖缺口 | `pysmx/test/`、各未测模块 | 部分 |
| P2 | 测试发现脆弱 | `scripts/run_smx_tests.py` | ✅ |
| P3 | 纯 Python 性能 | `scripts/benchmark.py`、各 `_*.py` | 待处理 |
| P4 | 版本声明矛盾 | `pyproject.toml` | ✅ |
| P4 | 缺 pyproject [project] | `pyproject.toml` | ✅ |
| P4 | 依赖管理混乱 | `requirements*.txt` | ✅ |
| P4 | CI 无质量门禁 | `.github/workflows/test.yml` | 部分 |
| P5 | API 风格割裂 | `pysmx/SM2`、`SM3`、`SM4` | 待处理 |
| P5 | extra 未导出 | `pysmx/extra/__init__.py` | ✅ |
| P5 | 文档缺口 | `doc/`、`README*` | 待处理 |
