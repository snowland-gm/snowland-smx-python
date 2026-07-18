# snowland-smx 性能对比（pysmx vs gmssl / gmssl-pyx）

本文档由 `benchmark.py` 自动生成，请勿手动修改。

## 测试环境

- Python: 3.13.5
- 对比库 gmssl: 已启用
- 对比库 gmssl-pyx: 已启用
- 数据规模: 64 B / 1 KB / 16 KB
- 生成时间: 2026-07-18 18:50:40
- 复现命令: `py benchmark.py --quick`

> speedup = pysmx MB/s ÷ 对比库 MB/s

> 注：gmssl-pyx 的 SM4 仅提供 CBC 模式（无 ECB），且其 SM2 明文上限为 255 字节，故 SM2 基准统一使用 64 字节明文。

## SM2

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| keygen | - | 8.8 | 0.0 | - |
| encrypt | 64 B | 8.8 | 0.0 | - |
| gmssl | | 8.4 | 0.0 | 1.04x |
| gmssl-pyx | | 8.2 | 0.0 | 1.08x |
| decrypt | 64 B | 5.3 | 0.0 | - |
| gmssl | | 2.3 | 0.0 | 2.25x |
| gmssl-pyx | | 3.8 | 0.0 | 1.40x |
| sign | 64 B | 4.3 | 0.0 | - |
| gmssl | | 3.6 | 0.0 | 1.19x |
| gmssl-pyx | | 5.4 | 0.0 | 0.79x |
| verify | 64 B | 7.6 | 0.0 | - |
| gmssl | | 5.9 | 0.0 | 1.30x |
| gmssl-pyx | | 8.5 | 0.0 | 0.90x |

## SM3

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| hash | 64 B | 4.9 | 0.0 | - |
| gmssl | | 9.9 | 0.0 | 0.49x |
| gmssl-pyx | | 7.1 | 0.0 | 0.69x |
| hash | 1 KB | 9.9 | 0.0 | - |
| gmssl | | 5.4 | 0.0 | 1.84x |
| gmssl-pyx | | 1.5 | 0.0 | 6.49x |
| hash | 16 KB | 8.2 | 0.1 | - |
| gmssl | | 4.1 | 0.1 | 2.02x |
| gmssl-pyx | | 2.0 | 0.0 | 4.01x |

## SM4

### ECB

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| ecb_encrypt | 64 B | 3.8 | 0.0 | - |
| gmssl | | 6.4 | 0.0 | 0.59x |
| ecb_decrypt | 64 B | 9.2 | 0.0 | - |
| gmssl | | 6.1 | 0.0 | 1.50x |
| ecb_encrypt | 1 KB | 6.0 | 0.0 | - |
| gmssl | | 1.8 | 0.0 | 3.36x |
| ecb_decrypt | 1 KB | 3.3 | 0.0 | - |
| gmssl | | 2.5 | 0.0 | 1.29x |
| ecb_encrypt | 16 KB | 6.7 | 0.1 | - |
| gmssl | | 8.8 | 0.1 | 0.77x |
| ecb_decrypt | 16 KB | 6.7 | 0.1 | - |
| gmssl | | 4.8 | 0.1 | 1.39x |

### CBC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| cbc_encrypt | 64 B | 5.9 | 0.0 | - |
| gmssl | | 9.4 | 0.0 | 0.62x |
| gmssl-pyx | | 4.3 | 0.0 | 1.36x |
| cbc_decrypt | 64 B | 4.6 | 0.0 | - |
| gmssl | | 7.6 | 0.0 | 0.60x |
| gmssl-pyx | | 3.9 | 0.0 | 1.18x |
| cbc_encrypt | 1 KB | 4.1 | 0.0 | - |
| gmssl | | 2.0 | 0.0 | 2.03x |
| gmssl-pyx | | 9.7 | 0.0 | 0.43x |
| cbc_decrypt | 1 KB | 4.8 | 0.0 | - |
| gmssl | | 3.3 | 0.0 | 1.46x |
| gmssl-pyx | | 4.6 | 0.0 | 1.04x |
| cbc_encrypt | 16 KB | 7.6 | 0.1 | - |
| gmssl | | 5.5 | 0.1 | 1.37x |
| gmssl-pyx | | 8.8 | 0.1 | 0.86x |
| cbc_decrypt | 16 KB | 4.8 | 0.1 | - |
| gmssl | | 6.4 | 0.1 | 0.74x |
| gmssl-pyx | | 6.4 | 0.1 | 0.74x |

## ZUC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| encrypt | 64 B | 4.2 | 0.0 | - |
| encrypt | 1 KB | 7.6 | 0.0 | - |
| encrypt | 16 KB | 6.3 | 0.1 | - |
