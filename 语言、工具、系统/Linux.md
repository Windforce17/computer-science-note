# 通用
## systemd
这是唯一一种内核级别的保活工具。虽然超级臃肿，不得不用。
systemd相关的命令，大多数人应该只用过sytemctl.
这个命令加上—H user@host 可以远程管理其他机器的systemd

- bootctl: 管理 EFI 和 boot loader
- busctl: D-Bus 监控
- coredumpctl: coredump 处理
- homectl: Home 目录管理
- hostnamectl: hostname 配置
- journalctl: 日志
- kernel-install: 内核和 initramfs 管理
- localectl: locale 和键盘布局配置
- loginctl: login manager 配置
- machinectl: 虚拟机、容器管理
- networkctl: 网络管理
- oomctl: OOM 配置
- portablectl: 可移植服务镜像配置
- resolvectl: 域名解析
- systemctl: 服务管理
- timedatectl: 时间管理
- udevadm: udev 管理
- userdbctl: 用户管理
### unit

unit有这几种，写unit时扩展名要写对.
services (_.service_)
不加扩展名一律认为是service
mount points (_.mount_)
/home和home.mount(不一定是文件)等价
devices (_.device_) 
/dev/sda2和(dev-sda2)等价
sockets (_.socket_)

unix区分system和user两套配置，systemctl不加--user默认是--system
带@符号是一个实例，unit只是模板，@后是实例名
文件结构：
 \[unit\]
包含通用的一些配置，unit名称等。
- Description 
名称
- Documentation 
文档url
- After 
只在after列出后的unit启动后才会启动
- Before 
和After相反
- Require
列出的unit会被启动
- Wants 
和After相比，不强制要求列出的unit启动
- Conflicts 
和After相反，列出的unit不能启动

\[{unit type}\]
不同的unit类型，描述不同。
\[service\]
service 是最常用的，大部分情况下写service就足够了
- Type 
不同的Type会影响ExecStart等相关选项,下面是Type的几种选项
simple 默认值，ExecStart启动的主进程就是对应的service
forking 进程fork出来的子进程是对应的service，主进程退出则启动成功
oneshot 和simple相似，但是进程要退出
dbus 和simple相似，units 获得D-bus 名称后才算启动
notify 和simple相似，进程必须使用`sd_notify()` 函数发送消息才算启动
idle 和simple相似，实际实行的文件等待所有jobs完成后。
- ExecStart
启动命令。ExecStartPre和ExecStartPost分别是启动前和启动后执行的命令
- ExecStop
结束时执行的命令
- ExecReload
执行reload时执行的命令
- Restart
重启策略，启用后服务在进程完全退出后重启并清理异常
- RemainAfterExit
设置为True后，进程退出后依然认为启动成功。
- PIDFile
存放PID的文件
- Environment
环境变量
- RestartSec
重启间隔
\[install\]
执行systemctl enable 时的一些信息
- Alias
除了enable 其他命令可以使用列出的别名
RequireBy 启用时列出的unit也会启动
WantedBy  列出的unit和service中的Wants相同
Also 列出的unit会同时安装或卸载
DefaultInstance unit限制

### systemctl
systemctl status {unit|pid} 查看信息
systemctl list-units 列出所有units
systemctl list-unit-files 列出所有units文件，可以加--state=masked 列出被masked的unit
systemctl start|stop|restart {unit}  启动停止重启一个unit
systemctl enable|disable {unit}  开机启动|不开机启动一个unit，加上--now参数立即start|stop
systemctl daemon-reload 刷新所有unit配置重新读取，需要root权限
systemctl reenable {unit} 禁止并立即启用unit开启启动，修改了\[ Install\] 部分需要执行
systemctl mask {unit} 禁止启动一个unit，不删除文件
systemctl unmask {unit} 让一个unit可以被启动

除此之外，systemd也可以电源管理.
优先读取：/etc/systemd/system/ 目录下的unit文件，其次是/usr/lib/systemd/system/


### target
一个target是多个unit的组合。使用`systemctl list-units --type=target` 列出所有target。
默认target：systemctl get-default
系统启动会抵达默认target


## 磁盘扩容与LVM
LVM是Linux 内核自带的一种磁盘工具，可以把物理磁盘抽象出来，跨磁盘创建分区，组建raid等。
通过分区或者磁盘本身创建pv（Physical Volume）。一个分区或磁盘可以创建一个pv
通过pv创建vg（Volume Group），一个vg可以包含多个pv，vg可以看成是我们用的磁盘。
通过vg创建lv（Logical Volume），一个vg可以创建多个lv，lv可以看成是我们用的分区。

（其实你可以直接把一块磁盘格式化成ext4文件系统然后挂载，这样就没有/dev/sda1了，而是直接/dev/sda,LVM同理)

### 在线扩容磁盘
有时候vmware分的磁盘小了，需要扩容，可以按照如下操作。
vmware的磁盘扩容不能有快照，所有快照都要删除。
#todo 
图
命令：
1. 先选中需要扩容的磁盘，开启parted
sudo parted /dev/sda3 

2. 查看对应的分区号，输入p回车。
我这里使用了lvm，并且已经扩容过了。注意，扩容的分区只能是最后一个。
```sh
(parted) p                                                                
Model: VMware, VMware Virtual S (scsi)
Disk /dev/sda: 129GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End     Size    File system  Name  Flags
 1      1049kB  2097kB  1049kB                     bios_grub
 2      2097kB  2150MB  2147MB  ext4
 3      2150MB  129GB   127GB
 
```
3. 扩容最后一个分区
输入resizepart 3
最后输入100% 回车，就可以扩容最后一个分区了
```
(parted) resizepart 3 
End?  [107GB]? 100%
```

4. 扩容文件系统
分区扩容后还需要扩容文件系统
如果是LVM的话，稍微有些麻烦，需要先扩容pv，然后扩容vg，最后扩容LV后，扩容文件系统。
- 扩容pv:
```sh
pwn@ubuntu:~% sudo pvresize /dev/sda3
pwn@ubuntu:~% sudo pvs                     
  PV         VG        Fmt  Attr PSize    PFree 
  /dev/sda3  ubuntu-vg lvm2 a--  <118.00g 20.00g
```
- 扩容vg:
因为我pv里只有一个vg，所以已经显示出还有20G的空闲空间，其他情况可能需要vgextend命令来扩容
```sh
pwn@ubuntu:~% sudo vgs                      
  VG        #PV #LV #SN Attr   VSize    VFree 
  ubuntu-vg   1   1   0 wz--n- <118.00g 20.00g
pwn@ubuntu:~% sudo vgdisplay
  --- Volume group ---
  VG Name               ubuntu-vg
  System ID             
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  13
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               1
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <118.00 GiB
  PE Size               4.00 MiB
  Total PE              30207
  Alloc PE / Size       25087 / <98.00 GiB
  Free  PE / Size       5120 / 20.00 GiB
  VG UUID               E9wWPI-JbbE-pd6I-di0m-rmnC-0LTK-tMeKEU
  
```
- 扩容LV：
```sh
pwn@ubuntu:~% sudo lvextend -l +100%free /dev/ubuntu-vg/ubuntu-lv         
  Size of logical volume ubuntu-vg/ubuntu-lv changed from <98.00 GiB (25087 extents) to <118.00 GiB (30207 extents).
  Logical volume ubuntu-vg/ubuntu-lv successfully resized.
pwn@ubuntu:~%
```
- 扩容文件系统
扩容lv后，发现文件系统还是原来大小，最后在线扩容文件系统即可，不同的文件系统命令不同，常用的ext4文件系统使用resize2fs即可
```sh
pwn@ubuntu:~% df -h           
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              389M  1.6M  388M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   97G   60G   33G  65% /
tmpfs                              1.9G     0  1.9G   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              1.9G     0  1.9G   0% /run/qemu
/dev/sda2                          2.0G  247M  1.6G  14% /boot
tmpfs                              389M  4.0K  389M   1% /run/user/1000
pwn@ubuntu:~% sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
resize2fs 1.46.5 (30-Dec-2021)
Filesystem at /dev/mapper/ubuntu--vg-ubuntu--lv is mounted on /; on-line resizing required
old_desc_blocks = 13, new_desc_blocks = 15
The filesystem on /dev/mapper/ubuntu--vg-ubuntu--lv is now 30931968 (4k) blocks long.
pwn@ubuntu:~% df -h
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              389M  1.6M  388M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv  116G   60G   52G  54% /
tmpfs                              1.9G     0  1.9G   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              1.9G     0  1.9G   0% /run/qemu
/dev/sda2                          2.0G  247M  1.6G  14% /boot
tmpfs                              389M  4.0K  389M   1% /run/user/1000

```

如果没用LVM，直接输入`sudo resize2fs {分区路径}` 即可

### 其他LVM相关命令
#### 创建

- `pvcreate /dev/sd{b,c}1`
- `vgcreate <VGNAME> <dev name>`
- `lvcreate -L <SIZE> -n <LV_NAME> <VG_NAME>`
- `lvcreate -l <SIZE%>vg -n <LV_NAME> <VG_NAME>`
- `lvcreate -l <SIZE>free -n <LV_NAME> <VG_NAME>`

#### 扩展

- `vgextend <vgname> <pv path>`
- `lvextend -L [+]SIZE <lv path>` Physical boundary
- `resize2fs <lv path>` Logical boundary
- `e2fsck <lv path>` Check file system

#### 减小

- `e2fsck -f <lv path>` Check file system
- `resize2fs <lv path> <SIZE>` Reduce logical boundary
- `lvreduce -L [-]SIZE <lv path>` Physical boundary