# 加固
先提权，不少加固操作需要root权限,有了root权限后可以禁ip等。
[[提权]]

## patch
## 整数溢出

无符号跳转
JA	无符号大于则跳转
JNA	无符号不大于则跳转
JAE	无符号大于等于则跳转（同JNB）
JNAE	无符号不大于等于则跳转（同JB）
JB	无符号小于则跳转
JNB	无符号不小于则跳转
JBE	无符号小于等于则跳转（同JNA）
JBNE	无符号不小于等于则跳转（同JA）

有符号跳转
JG	有符号大于则跳转
JNG	有符号不大于则跳转
JGE	有符号大于等于则跳转（同JNL）
JNGE	有符号不大于等于则跳转（同JL）
JL	有符号小于则跳转
JNL	有符号不小于则跳转
JLE	有符号小于等于则跳转（同JNG）
JNLE	有符号不小于等于则跳转（同JG）



## 栈溢出
直接patch 读大小即可

## 格式化字符串
修改printf等函数参数

## 堆溢出
大部分情况直接nop free函数即可。
不允许nop free函数则需要patch 溢出点。
额外代码可以写在eh_frame段内。
## 沙箱技术
#todo 
https://www.shuzhiduo.com/A/rV57A30WzP/
https://www.anquanke.com/post/id/219077
Linux自带了SECCOMP限制系统调用。
```c
// 函数原型
#include <sys/prctl.h>
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
// option选项有很多，剩下的参数也由option确定，这里介绍两个主要的option
// PR_SET_NO_NEW_PRIVS(38) 和 PR_SET_SECCOMP(22)
// option为38的情况
// 此时第二个参数设置为1，则禁用execve系统调用且子进程一样受用
prctl(38, 1LL, 0LL, 0LL, 0LL);
// option为22的情况
// 此时第二个参数为1，只允许调用read/write/_exit(not exit_group)/sigreturn这几个syscall
// 第二个参数为2，则为过滤模式，其中对syscall的限制通过参数3的结构体来自定义过滤规则。
prctl(22, 2LL, &v1);
```