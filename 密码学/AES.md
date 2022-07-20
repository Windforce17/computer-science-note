# 总体加密过程
![[总体加密过程.png]]

1. AES加密算法不是*feistel*结构
2. 在开始和结束中的**轮密钥加**阶段使用密钥，如果不在开始或结束阶段使用，那么在不知道密钥的情况下就可以计算器逆，故不能增加安全性。
3. 本身轮密钥加不难破解，但是其他三个阶段提供了**混淆、扩散** 以及非线性功能。所以非常有效和安全，缺一不可。
4. 虽然解密算法按逆序方式扩展了密钥，但解密算法和加密算法并不一样。
5. 最后一轮只有三个阶段，使得加密算法可逆。
6. 明文分组长度是16字节，密钥长度根据AES-128、AES-192、AES-256变化。
2. 共四个阶段，一个置换和三个代替：
  - 字节代替：使用S 盒替换字节
  - 行移位： 行移位，一个简单的置换
  - 列混淆： 在 $GF(2^n)$上进行一个矩阵乘法
  - 轮密钥加：按位XOR

## S-box 构造
1. 初始化，`[0x00 0x01 0x02...0x0f]`作为一行，这样就有一个$16 \times 16$的二维数组，第a行b列的值为0xab.

2. 上面每个数求得在有限域$GF(2^8)$中的逆，0x00还是 映射为00

3. 记S盒中每个字节为 $b_7b_6b_5b_4b_3b_2b_1b_0$,对S盒中每个字节做如下变换:

$$b_i=b_i \oplus b_{i+4\mod 8} \oplus b_{i+5\mod 8} \oplus b_{i+6 \mod 8} \oplus b_{i+7\mod 8} \oplus c_i$$

其中`c=0x63`。这个过程可以用下面的矩阵标示：

$$

\begin{bmatrix}

b_0\\

b_1\\

b_2\\

b_3\\

b_4\\

b_5\\

b_6\\

b_7\\

\end{bmatrix}

=

\begin{bmatrix}

1 & 0 & 0 & 0 & 1 & 1 & 1 & 1 \\

1 & 1 & 0 & 0 & 0 & 1 & 1 & 1 \\

1 & 1 & 1 & 0 & 0 & 0 & 1 & 1 \\

1 & 1 & 1 & 1 & 0 & 0 & 0 & 1 \\

1 & 1 & 1 & 1 & 1 & 0 & 0 & 0 \\

0 & 1 & 1 & 1 & 1 & 1 & 0 & 0 \\

0 & 0 & 1 & 1 & 1 & 1 & 1 & 0 \\

0 & 0 & 0 & 1 & 1 & 1 & 1 & 1 \\

  

\end{bmatrix}

  

\begin{bmatrix}

b_0\\

b_1\\

b_2\\

b_3\\

b_4\\

b_5\\

b_6\\

b_7\\

\end{bmatrix}

+

\begin{bmatrix}

1\\

1\\

0\\

0\\

0\\

1\\

1\\

0\\

\end{bmatrix}

  

$$

4. 根据矩阵运算规则，很容易推导出逆矩阵的运算公式：

$$b_i= b_{i+2\mod 8} \oplus b_{i+5\mod 8} \oplus b_{i+7 \mod 8} \oplus d_i$$

其中`d=0x5`

## 行变换
有正向和逆向操作，正向操作如下
![[Pasted image 20220623155421.png]]

1. 第1行不变
2. 第2行循环左移1个字节
3. 第3行循环左移2个字节
4. 第4行循环左移3个字节
## 列混淆变换

  ![[Pasted image 20220623155602.png]]
实际上就是矩阵乘法，不过要注意的是这个乘法和加法是在$GF(2^8)$上进行的。
逆向变换只需要乘以逆矩阵，这个逆矩阵也是在$GF(2^8)$上得到。

![[Pasted image 20220623155659.png]]


## AES密钥扩展
密钥扩展算法看起来比较复杂，实际上是用简单的运算复合而成。输入16字节，输出176字节，作用于每一轮加密中的最后一个阶段。这个算法不是很复杂，还是由基本的异或，移位，字节代替完成。伪代码如下：

```c
// 这里一个字是4字节m,输入key，输出w
AES_key_expansion(byte key[16], word w[44])
{
  word temp;
  for(i=0;i<4;i++){
    // 初始化w数组，将key复制到w前4个word中
    w[i]={key[4*i],key[4*i+1],key[4*i+2],key[4*i+3]}
  }
  //前4个已经初始化过了，从第5个字开始做字节扩展
  for(i=4;i<44;i++){
    //上一组key
    temp=w[i-1];
    //新的一组key，更新temp
    if(i %4==0){
    //字节移位，循环左移一个字节，[0,1,2,3] -> [1,2,3,0]
      temp=Rotword(temp);
    // 从S盒中进行替换
      temp=SubWord(temp);
    //Rcon是固定的，每一轮的值不同，如下：
    //Rcon={0x01000000,0x02000000,0x04000000...}
    //第2 3 4字节都为0，第一个字节为上一组二倍，当然，乘2是在域GF(2^8)进行的。
      temp^=Rcon[i/4];
    }
    //最后和temp作xor运算。
    w[i]=w[i-4]^temp
  }
}
```

作用：防止已有的密码分析攻击。使用不同的Rcon（轮常量）可以防止轮密钥产生的对称性和相似性。  

密钥扩展算法标准：
1. 知道密钥或者轮密钥某些位不能计算出其他位。
2. 可逆变换。
3. 能够在各种处理器上执行。
4. 密钥每个位都会影响轮密钥产生。
5. 简单。

参考资料：
1.《密码编码学与网络空间安全——原理与实践（第六版）》.William Stallings

# 分组密码模式
分组密码加密每次使用b位固定长度来进行加密，输出b位的密文，加密明文如果大于了b位，则就需要分组，这其中会引发很多安全问题。目前定义了5种“工作模式”。这些可以适用于任何分组密码，例如AES和3DES。

## 电码本（ECB）
最简单，使用相同密钥对明文独立加密。  
应用：单个分组安全传输，加密一个固定长度密钥。

缺点：明文相同的分组，密文也会相同。可以使用已知明文攻击

## 密文分组链接（CBC）
输出的是上一个加密后的分组和当前明文分组的异或结果。第一个分组可以使用初始向量（IV）进行异或。IV被更改，则解密出的明文也被篡改。  
认证，面向分组的通用传输。
缺点：不能并行计算，依赖于上一个分组的加密结果。

## 密文反馈（CFB）
流密码：密文和明文等长。
一次处理s位，上一块密文作为加密算发的输入，产生的伪随机数和下一组明文异或。初始化b位移位寄存器，值为IV，加密函数输出最左边s位和明文第一个分段P1异或后得到C1，发送C1，移位寄存器左移s位，C1填入移位寄存器最右边s位。直到明文单元都被加密完。  
设$MSB_s(X)$是X的最左边s位。则$C_1=P_1 \oplus MSB_s(E(K,IV))$，$P_1=C_1 \oplus MSB_s(E(K,IV))$
用处：面向数据流的通用传输

## 输出反馈（OFB）
加密算法按输入是上一次加密的输出，使用整个分组。和CFB相似，使用整个明文和密文分组进行运算，而CFB仅使用s位子集。加密标示如下：$C_j=P_j\oplus E(K,(C_{j-1} \oplus P_{j-1}))$。
优点：某位出现错误，不会影响其他位。
缺点：抗篡改不行。

噪音信道上的数据流传输（卫星通信） 

## 计数器（CTR）
每个明文分组和一个经过加密的计数器作异或，计数器递增。加密：$C_j=P_j \oplus E(K,T_j)$，最后一组长度可能小于一个分组，那么我们仅可以使用相应的位数即可，不需要填充一个分组，即$C_N=P_N \oplus MSB_u(E(K,T_N))$  
用途和优点  ：面向分组的通用传输，用于高速需求，可并行计算，随机访问，和其他模式一样安全。

# 实现
## python
```python
#!/usr/bin/env python3

from hashlib import md5
from base64 import b64decode
from base64 import b64encode

import zlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        # best use difference iv
        iv = self.key
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data, 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.key)
        return self.cipher.decrypt(raw)


if __name__ == '__main__':
    msg="1Xe26YrOsTDb+Az7vnzssh12E05z8aniqwYWRWaVG1svP3Gq1kx+lWMFPVFRjP2J7YyzWbFCC1qFH4EqYdxI37r3fmlCntJTJB/UiOnk4IhlFE5HUoZH2ZQBEHIh1UpJ"
    cte = msg
    pwd = b"0123456789ABCDEF"


    dec=zlib.decompressobj(32+zlib.MAX_WBITS)
    plantext=AESCipher(pwd).decrypt(cte)
    plantext=dec.decompress(plantext)
    print(plantext)

```

## rust
```rust
use aes::{Aes128, Aes128Dec};
use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
type Aes128CbcDec = Decryptor<aes::Aes128>;

pub fn decrypt_aes128(key: &[u8; 16], data: &mut [u8]) -> Vec<u8> {
    Aes128CbcDec::new(key.into(), key.into())
        .decrypt_padded_mut::<Pkcs7>(data)
        .unwrap()
        .to_vec()
}

#[test]
fn test_demo_decrypt() {
    let key = "0123456789ABCDEF";
    let iv = "0123456789ABCDEF";
    let data = "NQN4xB6m0CBjzWl1/IGtwyzp9BWxgZLkCBcoVcNleJU=";

    // let key = base64::decode(key).unwrap();
    // let iv = base64::decode(iv).unwrap();
    let data = base64::decode(data).unwrap();
    let key = key.as_bytes();
    let result = decrypt_aes128(&key.try_into().unwrap(), &mut data.clone()[..]);
    let _result = String::from_utf8(result).unwrap();
    println!("{}", _result);
}

```