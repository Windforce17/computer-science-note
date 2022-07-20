# re
## open-source
纯数学题，注意第二个参数，`(second % 17) * 11` 恒等于88
flag:(second % 17) * 11

## simple-unpack
#脱壳
upx -d 结束。
flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}

## re1
来源如dauctf 明文flag
DUTCTF{We1c0met0DUTCTF}

## logmein
简单的xor加密
```rs
fn main() {
    let mut s = r#":"AL_RT^L*.?+6/46"#.as_bytes().to_owned();
    let key = "harambe".as_bytes().to_owned();
    s.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(x, k)| *x ^= *k);
    println!("s:{} ", String::from_utf8(s).unwrap());
}
```

## python-trade
pyc反编译，使用pycdc即可。
nctf{d3c0mpil1n9_PyC}
```py
# Source Generated with Decompyle++
# File: f417c0d03b0344eb9969ed0e1f772091.pyc (Python 2.7)

import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)
    
    return base64.b64encode(s)

correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
flag = ''
print 'Input flag:'
flag = raw_input()
if encode(flag) == correct:
    print 'correct'
else:
    print 'wrong'
```

```rs
fn main() {
    let mut s = base64::decode("XlNkVmtUI1MgXWBZXCFeKY+AaXNt").unwrap();
    s.iter_mut().for_each(|x| *x = (*x - 16) ^ 32);
    println!("{}", String::from_utf8(s).unwrap());
}
```
## no-strings-attached
下断点看内存即可
```py
>>> a=[57,52,52,55,123,121,111,117,95,97,114,101,95,97,110,95,105,110,116,101,114,110,97,116,105,111,110,97,108,95,109,121,115,116,101,114,121,125]
>>> print("".join([chr(i) for i in a]))
9447{you_are_an_international_mystery}
```

## csaw2013reversing2
使用angr模拟，直接读内存。flag{reversing_is_not_that_hard!}
```py
import angr
import claripy

print("start")
project=angr.Project("0453d21297a743e199d8a7de75179e52.exe",auto_load_libs=False)
@project.hook(0x04010A3)
def hook_printf(state):
    print(state.memory.load(0xb00000, 0x24))
    project.terminate_execution()

st=project.factory.blank_state(addr=0x401000)

data_addr=0xb00000
for i in range(0x24):
    st.memory.store(data_addr+i,st.memory.load(0x409B10+i,1))

st.regs.edx=0xb00000
# st.regs.ecx=0xb00000

st.regs.edi=0
sm=project.factory.simulation_manager(st)
sm.explore(find=0x0401029)
print(sm.found[0].memory.load(0xb00000,0x24))
ss=sm.found[0]
ss.solver.eval(sm.found[0].memory.load(0xb00000,0x24),cast_to=bytes)
```

## getit66
SharifCTF{b70c59275fcfa8aebf2d5911223c6589}
调试+读内存
```py
import angr
import claripy

print("start")
project=angr.Project("e3dd9674429f4ce1a25c08ea799fc027",auto_load_libs=False)
st=project.factory.entry_state()

sm=project.factory.simulation_manager(st)
sm.explore(find=0x4007E2)
```

## Shuffle1
签到
SECCON{Welcome to the SECCON 2014 CTF!}

## SRM50
IDA里有明文比较:CZ9dmq4c8g9G7bAX

## Mysterious11
ida里可以看到输出122xyz 然后会弹出:flag{123_Buff3r_0v3rf|0w}

## maze
南邮ctf原题 走迷宫

nctf{o0oo00O000oooo..OO}

## re4-unvm-me
使用pyc反编译后就是明文
ALEXCTF{dv5d4s2vj8nk43s8d8l6m1n5l67ds9v41n52nv37j481h3d28n4b6v3k}


## 流浪者
'KanXueCTF2019JustForhappy‘
```py
import angr
import claripy

print("start")
project=angr.Project("cm.exe",auto_load_libs=False)
st=project.factory. blank_state(addr=0x4017F0,auto_load_libs=False)

sm=project.factory.simulation_manager(st)
sm.explore(find=0x0401873)
ss=sm.found[0]
ss.solver.eval(sm.found[0].memory.load(ss.regs.ebp-0x24,0x32),cast_to=bytes)
```


## game 
调试器里直接调用目标函数就出来了
zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}
# mobile
## app1
`buildConfig` 类中的VERSION_CODE和VERSION_NAME互相异或
```java
public final class BuildConfig {
    public static final String APPLICATION_ID = "com.example.yaphetshan.tencentgreat";
    public static final String BUILD_TYPE = "debug";
    public static final boolean DEBUG = Boolean.parseBoolean("true");
    public static final String FLAVOR = "";
    public static final int VERSION_CODE = 15;
    public static final String VERSION_NAME = "X<cP[?PHNB<P?aj";
}

```

```py
"".join([chr(ord(i)^15) for i in a])
```
flag:W3l_T0_GAM3_0ne
