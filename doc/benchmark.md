# snowland-smx 性能对比（pysmx vs gmssl / gmssl-pyx）

本文档由 `scripts/benchmark.py` 自动生成，请勿手动修改。

## 测试环境

- Python: 3.13.5
- 对比库 gmssl: 已启用
- 对比库 gmssl-pyx: 已启用
- 数据规模: 64 B / 1 KB / 64 KB / 1 MB
- 生成时间: 2026-08-21 14:13:04
- 复现命令: `py scripts/benchmark.py --quick`

> speedup = pysmx MB/s ÷ 对比库 MB/s

> 注：gmssl-pyx 的 SM4 仅提供 CBC 模式（无 ECB），且其 SM2 明文上限为 255 字节，故 SM2 基准统一使用 64 字节明文。

## SM2

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| keygen | - | 6.4 | 0.0 | - |
| encrypt | 64 B | 5.9 | 0.0 | - |
| gmssl | | 5.0 | 0.0 | 1.19x |
| gmssl-pyx | | 2.5 | 0.0 | 2.41x |
| decrypt | 64 B | 2.2 | 0.0 | - |
| gmssl | | 3.4 | 0.0 | 0.66x |
| gmssl-pyx | | 2.5 | 0.0 | 0.89x |
| sign | 64 B | 2.7 | 0.0 | - |
| gmssl | | 6.0 | 0.0 | 0.45x |
| gmssl-pyx | | 2.9 | 0.0 | 0.92x |
| verify | 64 B | 2.3 | 0.0 | - |
| gmssl | | 6.1 | 0.0 | 0.38x |
| gmssl-pyx | | 6.3 | 0.0 | 0.37x |

## SM3

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| hash | 64 B | 1.9 | 0.0 | - |
| gmssl | | 3.5 | 0.0 | 0.53x |
| gmssl-pyx | | 4.0 | 0.0 | 0.47x |
| hash | 1 KB | 3.1 | 0.0 | - |
| gmssl | | 2.3 | 0.0 | 1.35x |
| gmssl-pyx | | 7.3 | 0.0 | 0.43x |
| hash | 64 KB | 0.5 | 0.0 | - |
| gmssl | | 1.5 | 0.1 | 0.33x |
| gmssl-pyx | | 9.1 | 0.6 | 0.05x |
| hash | 1 MB | 0.3 | 0.3 | - |
| gmssl | | 0.2 | 0.2 | 1.58x |
| gmssl-pyx | | 4.2 | 4.2 | 0.06x |

## SM4

### ECB

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| ecb_encrypt | 64 B | 4.3 | 0.0 | - |
| gmssl | | 5.7 | 0.0 | 0.76x |
| ecb_decrypt | 64 B | 9.4 | 0.0 | - |
| gmssl | | 9.3 | 0.0 | 1.01x |
| ecb_encrypt | 1 KB | 7.5 | 0.0 | - |
| gmssl | | 8.4 | 0.0 | 0.89x |
| ecb_decrypt | 1 KB | 7.5 | 0.0 | - |
| gmssl | | 2.9 | 0.0 | 2.62x |
| ecb_encrypt | 64 KB | 5.4 | 0.3 | - |
| gmssl | | 2.5 | 0.2 | 2.13x |
| ecb_decrypt | 64 KB | 9.9 | 0.6 | - |
| gmssl | | 3.6 | 0.2 | 2.76x |
| ecb_encrypt | 1 MB | 0.4 | 0.4 | - |
| gmssl | | 0.2 | 0.2 | 2.76x |
| ecb_decrypt | 1 MB | 1.1 | 1.1 | - |
| gmssl | | 0.1 | 0.1 | 8.16x |

### CBC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| cbc_encrypt | 64 B | 6.3 | 0.0 | - |
| gmssl | | 3.5 | 0.0 | 1.82x |
| gmssl-pyx | | 8.2 | 0.0 | 0.77x |
| cbc_decrypt | 64 B | 5.0 | 0.0 | - |
| gmssl | | 5.5 | 0.0 | 0.91x |
| gmssl-pyx | | 9.9 | 0.0 | 0.51x |
| cbc_encrypt | 1 KB | 1.8 | 0.0 | - |
| gmssl | | 5.4 | 0.0 | 0.34x |
| gmssl-pyx | | 3.8 | 0.0 | 0.49x |
| cbc_decrypt | 1 KB | 8.2 | 0.0 | - |
| gmssl | | 2.9 | 0.0 | 2.82x |
| gmssl-pyx | | 2.8 | 0.0 | 2.99x |
| cbc_encrypt | 64 KB | 6.8 | 0.4 | - |
| gmssl | | 1.7 | 0.1 | 3.87x |
| gmssl-pyx | | 4.6 | 0.3 | 1.46x |
| cbc_decrypt | 64 KB | 4.0 | 0.2 | - |
| gmssl | | 2.6 | 0.2 | 1.53x |
| gmssl-pyx | | 5.0 | 0.3 | 0.79x |
| cbc_encrypt | 1 MB | 0.7 | 0.7 | - |
| gmssl | | 0.1 | 0.1 | 4.81x |
| gmssl-pyx | | 4.0 | 4.0 | 0.16x |
| cbc_decrypt | 1 MB | 0.6 | 0.6 | - |
| gmssl | | 0.2 | 0.2 | 3.50x |
| gmssl-pyx | | 8.2 | 8.2 | 0.07x |

## ZUC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| encrypt | 64 B | 9.8 | 0.0 | - |
| encrypt | 1 KB | 5.4 | 0.0 | - |
| encrypt | 64 KB | 2.2 | 0.1 | - |
| encrypt | 1 MB | 0.1 | 0.1 | - |
