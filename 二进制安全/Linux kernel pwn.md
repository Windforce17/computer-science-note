# 常见文件

vmlinu： linux kernel，压缩后是bzImage，可能有多种压缩格式。

```Bash
zhichen@archlinux:~/ctf/kpwn% file vmlinuz    
vmlinuz: Linux kernel x86 boot executable bzImage, version 5.9.0-rc6+ (martin@martin) #10 SMP Sun Nov 22 16:47:32 CET 2020, RO-rootFS,
 swap_dev 0X7, Normal VGA
```

initramfs.cpio.gz : 文件系统 使用pio 和gzip压缩

run.sh: 一堆qemu的命令。

```Bash
#!/bin/sh
b 
```

-m 内存
-cpu cpu特性，smep和smap是两种kernel保护
-hdb 添加文件系统
-monitor /dev/null 禁用 qemu monitor，不然可能会有逃逸漏洞
-append 内核参数

  
# 解压和打包
解压内核，解压内核是为了得到Rop gadgets。
```Bash
#extract-image.sh
./extract-image.sh ./vmlinuz > vmlinux
```

```Bash
#!/bin/sh

# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
        # Use readelf to check if it's a valid ELF
        # TODO: find a better to way to check that it's really vmlinux
        #       and not just an elf
        readelf -h $1 > /dev/null 2>&1 || return 1

        cat $1
        exit 0
}

try_decompress()
{
        # The obscure use of the "tr" filter is to work around older versions of
        # "grep" that report the byte offset of the line instead of the pattern.

        # Try to find the header ($1) and decompress from here
        for        pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
        do
                pos=${pos%%:*}
                tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
                check_vmlinux $tmp
        done
}

# Check invocation:
me=${0##*/}
img=$1
if        [ $# -ne 1 -o ! -s "$img" ]
then
        echo "Usage: $me <kernel-image>" >&2
        exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```
解压文件系统cpio：
```sh
#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```
解压成功后，看一眼里面的etc/inittab 和etc/init.d/中的文件，这些定义了启动脚本。
如果后面启动内核时不是root的shell，按照下面修改启动脚本,把sh的uid和gid改回0
```sh
setuidgid 1000 /bin/sh
# Modify it into the following
setuidgid 0 /bin/sh
```
比如说这个initab就执行了rcS 然后改shell权限，最后关机
```sh
::sysinit:/etc/init.d/rcS
::once:-sh -c 'cat /etc/motd; setuidgid 1000 sh; poweroff'
```
因为root能读取一些信息便于开发exp，因此exp写完后还要该回去验证我们的exp
/proc/kallsyms 内核符号地址
/sys/module/core/sections/.text 内核.text段地址

写完exp后重新打包回initramfs
```bash
gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```
# Linux 内核保护
和用户态的程序相似，内核也有不少保护措施。
