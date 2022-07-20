# 基础知识
框架
```c
#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>        

static int lkm_init(void)
{
    printk("rootkit loaded\n");
    return 0;    
}

static void lkm_exit(void)
{
    printk("rootkit removed\n");
}

module_init(lkm_init);
//未定义清楚函数则不允许卸载这个module
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
```
makefile:
```c
obj-m                := rootkit.o

KBUILD_DIR        := /lib/modules/$(shell uname -r)/build

default:
        $(MAKE) -C $(KBUILD_DIR) M=$(shell pwd)
clean:
        $(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
```

## 内核debug
https://wusyong.github.io/posts/rust-kernel-module-00/
```shell
echo "add-auto-load-safe-path path/to/vmlinux-gdb.py" >> ~/.gdbinit
```
```shell
sudo qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage \
    -initrd qemu-initramfs.img \
    -M pc \
    -m 4G \
    -cpu Cascadelake-Server \
    -smp $(nproc) \
    -nographic \
    -vga none \
    -no-reboot \
    -append 'console=ttyS0 nokaslr' \
    -s -S
```
# 参考资料
https://github.com/PacktPublishing/Linux-Device-Drivers-Development
https://github.com/PacktPublishing/Linux-Device-Driver-Development-Cookbook
书籍：
[[Linux驱动程序开发实例（第2版）.pdf]]
[[Linux Device Drivers Development Develop customized drivers for embedded Linux (John Madieu) (z-lib.org).pdf]]