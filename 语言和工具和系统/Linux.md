# 通用
## 磁盘扩容
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

