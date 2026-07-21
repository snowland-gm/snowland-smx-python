# snowland-smx 性能对比（pysmx vs gmssl / gmssl-pyx）

本文档由 `scripts/benchmark.py` 自动生成，请勿手动修改。

## 测试环境

- Python: 3.13.5
- 对比库 gmssl: 已启用
- 对比库 gmssl-pyx: 已启用
- 数据规模: 64 B / 1 KB / 64 KB / 1 MB
- 生成时间: 2026-07-21 10:02:53
- 复现命令: `py scripts/benchmark.py --quick`

> speedup = pysmx MB/s ÷ 对比库 MB/s

> 注：gmssl-pyx 的 SM4 仅提供 CBC 模式（无 ECB），且其 SM2 明文上限为 255 字节，故 SM2 基准统一使用 64 字节明文。

## SM2

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| keygen | - | 6.0 | 0.0 | - |
| encrypt | 64 B | 5.6 | 0.0 | - |
| gmssl | | 7.8 | 0.0 | 0.71x |
| gmssl-pyx | | 6.4 | 0.0 | 0.86x |
| decrypt | 64 B | 7.5 | 0.0 | - |
| gmssl | | 7.6 | 0.0 | 0.99x |
| gmssl-pyx | | 7.3 | 0.0 | 1.03x |
| sign | 64 B | 3.7 | 0.0 | - |
| gmssl | | 6.1 | 0.0 | 0.61x |
| gmssl-pyx | | 8.1 | 0.0 | 0.46x |
| verify | 64 B | 5.3 | 0.0 | - |
| gmssl | | 10.0 | 0.0 | 0.53x |
| gmssl-pyx | | 9.1 | 0.0 | 0.58x |

## SM3

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| hash | 64 B | 4.0 | 0.0 | - |
| gmssl | | 4.3 | 0.0 | 0.92x |
| gmssl-pyx | | 9.4 | 0.0 | 0.42x |
| hash | 1 KB | 7.7 | 0.0 | - |
| gmssl | | 8.8 | 0.0 | 0.88x |
| gmssl-pyx | | 6.7 | 0.0 | 1.15x |
| hash | 64 KB | 3.3 | 0.2 | - |
| gmssl | | 2.9 | 0.2 | 1.12x |
| gmssl-pyx | | 7.0 | 0.4 | 0.47x |
| hash | 1 MB | 0.1 | 0.1 | - |
| gmssl | | 0.1 | 0.1 | 1.07x |
| gmssl-pyx | | 9.4 | 9.4 | 0.01x |

## SM4

### ECB

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| ecb_encrypt | 64 B | 4.9 | 0.0 | - |
| gmssl | | 5.6 | 0.0 | 0.88x |
| ecb_decrypt | 64 B | 9.3 | 0.0 | - |
| gmssl | | 4.3 | 0.0 | 2.19x |
| ecb_encrypt | 1 KB | 0.0 | 0.0 | - |
| gmssl | | 7.5 | 0.0 | 0.00x |
| ecb_decrypt | 1 KB | 0.7 | 0.0 | - |
| gmssl | | 6.8 | 0.0 | 0.11x |
| ecb_encrypt | 64 KB | 6.0 | 0.4 | - |
| gmssl | | 2.5 | 0.2 | 2.36x |
| ecb_decrypt | 64 KB | 8.1 | 0.5 | - |
| gmssl | | 1.5 | 0.1 | 5.46x |
| ecb_encrypt | 1 MB | 0.8 | 0.8 | - |
| gmssl | | 0.1 | 0.1 | 5.45x |
| ecb_decrypt | 1 MB | 0.7 | 0.7 | - |
| gmssl | | 0.1 | 0.1 | 5.09x |

### CBC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| cbc_encrypt | 64 B | 6.7 | 0.0 | - |
| gmssl | | 4.3 | 0.0 | 1.56x |
| gmssl-pyx | | 0.0 | 0.0 | 629.66x |
| cbc_decrypt | 64 B | 5.4 | 0.0 | - |
| gmssl | | 6.8 | 0.0 | 0.80x |
| gmssl-pyx | | 6.8 | 0.0 | 0.80x |
| cbc_encrypt | 1 KB | 7.2 | 0.0 | - |
| gmssl | | 7.1 | 0.0 | 1.00x |
| gmssl-pyx | | 8.3 | 0.0 | 0.87x |
| cbc_decrypt | 1 KB | 0.0 | 0.0 | - |
| gmssl | | 7.1 | 0.0 | 0.00x |
| gmssl-pyx | | 7.8 | 0.0 | 0.00x |
| cbc_encrypt | 64 KB | 7.1 | 0.4 | - |
| gmssl | | 2.6 | 0.2 | 2.69x |
| gmssl-pyx | | 6.0 | 0.4 | 1.18x |
| cbc_decrypt | 64 KB | 9.4 | 0.6 | - |
| gmssl | | 3.6 | 0.2 | 2.63x |
| gmssl-pyx | | 6.0 | 0.4 | 1.57x |
| cbc_encrypt | 1 MB | 0.6 | 0.6 | - |
| gmssl | | 0.1 | 0.1 | 5.42x |
| gmssl-pyx | | 9.4 | 9.4 | 0.06x |
| cbc_decrypt | 1 MB | 0.6 | 0.6 | - |
| gmssl | | 0.1 | 0.1 | 4.73x |
| gmssl-pyx | | 0.0 | 0.0 | 355.30x |

## ZUC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| encrypt | 64 B | 7.1 | 0.0 | - |
| encrypt | 1 KB | 5.9 | 0.0 | - |
| encrypt | 64 KB | 1.4 | 0.1 | - |
| encrypt | 1 MB | 0.1 | 0.1 | - |
