# snowland-smx

[![version](https://img.shields.io/pypi/v/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python?ref=badge_shield)
[![gitee](https://gitee.com/snowlandltd/snowland-smx-python/badge/star.svg)](https://gitee.com/snowlandltd/snowland-smx-python/stargazers)
[![github](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)
[![download](https://img.shields.io/pypi/dm/snowland-smx.svg)](https://pypi.org/project/snowland-smx)
[![wheels](https://img.shields.io/pypi/wheel/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![CodeFactor](https://www.codefactor.io/repository/github/astarchen/astartool/badge/master)](https://www.codefactor.io/repository/github/astarchen/astartool/overview/master)

安装:

pip 安装

**pip install snowland-smx**

或者

源码安装
**python setup.py install**

SM2

国密公钥加解密签名验签

  a. 密钥生成

```python
from pysmx.SM2 import generate_keypair
pk, sk = generate_keypair()
```

  签名

```python
from pysmx.SM2 import Sign
len_para = 64
sig = Sign("你好", sk, '12345678abcdef', len_para)
```
  验签
```python
from pysmx.SM2 import Verify
len_para = 64
Verify(sig, "你好", pk, len_para)
```

  加密
```python
from pysmx.SM2 import Encrypt
e = b'hello'
len_para = 64
C = Encrypt(e, pk, len_para, 0)  # 此处的1代表e是否是16进制字符串
```
  解密
```python
from  pysmx.SM2 import Decrypt
len_para = 64
m = Decrypt(C, sk, len_para)
```
## SM3
  国密哈希
  a. 方法1:

```python
from pysmx.SM3 import SM3
sm3 = SM3()
sm3.update('abc')
sm3.hexdigest()
```

  b. 方法2:

```python
from pysmx.SM3 import hash_msg
s = 'abc'
hash_msg(s)
```
## SM4
  国密私钥加解密
  a. 加密
```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
key_data = b'hello word errrr...'  # 16字节
sm4 = Sm4()
input_data = [1,2,3]
sm4.sm4_set_key(key_data, ENCRYPT)
msg = sm4.sm4_crypt_ecb()
```

  b. 解密
```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT
key_data = b'hello word errrr...'  # 至少16字节
sm4 = Sm4()
sm4.sm4_set_key(key_data, DECRYPT)
sm4.sm4_crypt_ecb(msg)
```

## SM9



## ZUC
  waiting for update

## License 

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python?ref=badge_large)