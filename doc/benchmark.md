# snowland-smx 性能对比（pysmx vs gmssl / gmssl-pyx）

本文档由 `scripts/benchmark.py` 自动生成，请勿手动修改。

## 测试环境

- Python: 3.13.5
- pysmx: 1.1.0
- 对比库 gmssl: 已启用 (版本 3.2.2)
- 对比库 gmssl-pyx: 已启用 (版本 2.1.0)
- 数据规模: 64 B / 1 KB / 64 KB / 1 MB
- 生成时间: 2026-09-29 19:30:11
- 复现命令: `py scripts/benchmark.py --quick`

> speedup = pysmx MB/s ÷ 对比库 MB/s

> 注：gmssl-pyx 的 SM4 仅提供 CBC 模式（无 ECB），且其 SM2 明文上限为 255 字节，故 SM2 基准统一使用 64 字节明文。

## SM2

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| keygen | - | 8.9 | 0.0 | - |
| encrypt | 64 B | 5.1 | 0.0 | - |
| gmssl | | 6.3 | 0.0 | 0.82x |
| gmssl-pyx | | 7.5 | 0.0 | 0.69x |
| decrypt | 64 B | 9.9 | 0.0 | - |
| gmssl | | 9.5 | 0.0 | 1.04x |
| gmssl-pyx | | 8.5 | 0.0 | 1.17x |
| sign | 64 B | 9.4 | 0.0 | - |
| gmssl | | 8.8 | 0.0 | 1.07x |
| gmssl-pyx | | 10.0 | 0.0 | 0.94x |
| verify | 64 B | 3.6 | 0.0 | - |
| gmssl | | 3.0 | 0.0 | 1.23x |
| gmssl-pyx | | 7.6 | 0.0 | 0.48x |

## SM3

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| hash | 64 B | 6.4 | 0.0 | - |
| gmssl | | 5.7 | 0.0 | 1.12x |
| gmssl-pyx | | 5.2 | 0.0 | 1.22x |
| hash | 1 KB | 6.6 | 0.0 | - |
| gmssl | | 5.7 | 0.0 | 1.15x |
| gmssl-pyx | | 4.5 | 0.0 | 1.48x |
| hash | 64 KB | 2.5 | 0.2 | - |
| gmssl | | 2.1 | 0.1 | 1.21x |
| gmssl-pyx | | 9.8 | 0.6 | 0.25x |
| hash | 1 MB | 0.2 | 0.2 | - |
| gmssl | | 0.1 | 0.1 | 1.58x |
| gmssl-pyx | | 7.0 | 7.0 | 0.03x |

## SM4

### ECB

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| ecb_encrypt | 64 B | 7.5 | 0.0 | - |
| gmssl | | 7.4 | 0.0 | 1.01x |
| ecb_decrypt | 64 B | 6.9 | 0.0 | - |
| gmssl | | 6.6 | 0.0 | 1.04x |
| ecb_encrypt | 1 KB | 9.9 | 0.0 | - |
| gmssl | | 5.6 | 0.0 | 1.76x |
| ecb_decrypt | 1 KB | 2.7 | 0.0 | - |
| gmssl | | 5.2 | 0.0 | 0.52x |
| ecb_encrypt | 64 KB | 7.5 | 0.5 | - |
| gmssl | | 2.9 | 0.2 | 2.59x |
| ecb_decrypt | 64 KB | 6.5 | 0.4 | - |
| gmssl | | 3.2 | 0.2 | 2.06x |
| ecb_encrypt | 1 MB | 0.8 | 0.8 | - |
| gmssl | | 0.2 | 0.2 | 4.26x |
| ecb_decrypt | 1 MB | 0.9 | 0.9 | - |
| gmssl | | 0.2 | 0.2 | 4.78x |

### CBC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| cbc_encrypt | 64 B | 5.6 | 0.0 | - |
| gmssl | | 9.8 | 0.0 | 0.57x |
| gmssl-pyx | | 8.2 | 0.0 | 0.68x |
| cbc_decrypt | 64 B | 2.3 | 0.0 | - |
| gmssl | | 6.4 | 0.0 | 0.36x |
| gmssl-pyx | | 8.2 | 0.0 | 0.28x |
| cbc_encrypt | 1 KB | 6.3 | 0.0 | - |
| gmssl | | 4.8 | 0.0 | 1.30x |
| gmssl-pyx | | 7.1 | 0.0 | 0.89x |
| cbc_decrypt | 1 KB | 6.9 | 0.0 | - |
| gmssl | | 9.8 | 0.0 | 0.71x |
| gmssl-pyx | | 10.0 | 0.0 | 0.70x |
| cbc_encrypt | 64 KB | 9.2 | 0.6 | - |
| gmssl | | 2.8 | 0.2 | 3.27x |
| gmssl-pyx | | 5.6 | 0.3 | 1.65x |
| cbc_decrypt | 64 KB | 7.5 | 0.5 | - |
| gmssl | | 2.8 | 0.2 | 2.64x |
| gmssl-pyx | | 8.3 | 0.5 | 0.91x |
| cbc_encrypt | 1 MB | 0.7 | 0.7 | - |
| gmssl | | 0.2 | 0.2 | 3.88x |
| gmssl-pyx | | 5.2 | 5.2 | 0.13x |
| cbc_decrypt | 1 MB | 0.5 | 0.5 | - |
| gmssl | | 0.2 | 0.2 | 2.57x |
| gmssl-pyx | | 8.3 | 8.3 | 0.06x |

## ZUC

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| encrypt | 64 B | 7.1 | 0.0 | - |
| encrypt | 1 KB | 8.4 | 0.0 | - |
| encrypt | 64 KB | 1.8 | 0.1 | - |
| encrypt | 1 MB | 0.1 | 0.1 | - |

## SM9

| operation | size | ops/s | MB/s | speedup (vs pysmx) |
| --- | --- | --- | --- | --- |
| master_keygen | - | 8.1 | 0.0 | - |
| gmssl-pyx | | 1.8 | 0.0 | - |
| user_sign_keygen | - | 9.8 | 0.0 | - |
| user_enc_keygen | - | 9.6 | 0.0 | - |
| gmssl-pyx | | 8.1 | 0.0 | - |
| sign | 48 B | 2.0 | 0.0 | - |
| verify | 48 B | 1.1 | 0.0 | - |
| encrypt | 48 B | 2.4 | 0.0 | - |
| gmssl-pyx | | 8.0 | 0.0 | 0.30x |
| decrypt | 48 B | 2.2 | 0.0 | - |
| gmssl-pyx | | 9.8 | 0.0 | 0.23x |
| kem_encapsulate | 32 B | 2.5 | 0.0 | - |
| kem_decapsulate | 32 B | 2.0 | 0.0 | - |
