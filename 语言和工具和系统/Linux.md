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
```
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
```
End?  [107GB]?
```

