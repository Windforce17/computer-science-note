# 802.11标准
802.11 定义了一套链路层协议，无线信号传输是在物理层
WiFi是 802.11的一个子集，由WiFi联盟管理
WiFi 写作 Wi-Fi
## 数据包寻址
与传统链路层不同的是，802.11 还包含了一个BSSID，是AP的唯一标识。因为AP的无线接口使用相同的MAC 地址。
数据包类型：Beacons、Deauthentication RTS CTF等
## 加密
WEP：静态40/104位公开密钥 使用RC4加密流
WPA-PSK 四次握手
![[wpa握手.png]]

预共享密钥（WiFi密码）在8~63位之间，结合SSID生成PMK，通过PMK生成PTK
每次在客户端连接时刷新PTK
PTK的创建需要 A-nonce,S-nonce,双方的MAC
在认证交换时通过检查MIC验证客户端是否有PMK

缺点：密码泄露就需要所有设备更换密码，不适合企业使用。

WPA企业模式：
PMK每次连接时通过认证服务器创建。
AP和认证服务通过RADIUS协议通信。
AP应只传输通往认证服务器的数据包。
![[WPA企业模式.png]]
EAP是扩展认证协议，让AP忽略具体认证协议细节。
# 扫描
分为主动扫描和被动扫描。

被动扫描：网卡监听信道即可
主动扫描：通过广播的方式发送探测数据包。**如果带ssid的话会被karma攻击**

在主动扫描中，客户端发送probe request，接收由AP发回的probe response。在被动扫描中，客户端在每个频道监听AP周期性发送的Beacon。之后是认证（Authentication）和连接（Association）过程。
![[主动和被动扫描.png]]
# 劫持
## karma

2004年，Dino dai Zovi和Shane Macaulay发布了Karma工具。Karma通过利用客户端主动扫描时泄露的已保存网络列表信息（preferred/trusted networks），随后伪造同名无密码热点吸引客户端自动连接。
![[探测主动扫描ssid.png]]
原理：
1.  主动扫描过程中（Active Scan）泄露客户端已保存网络列表信息   
    为实现自动连接已保存网络等功能，客户端会定时发送带有已保存网络信息的Probe Request（在后文统称为Directed Probe Request）。黑客通过无线网卡监听无线帧便能轻松获取这些信息。
    
2.  客户端对保存热点不检验MAC地址   
    为了增大信号覆盖范围，通常会部署多个同名热部署在整个区域。当客户端发现信号更强的同名热点，满足“一定条件”后便会切换过去，即所谓的无线漫游功能。为了实现这种特性同时也意味着，只需要SSID名称及加密方式相同客户端便能自动连接，不会检查MAC地址。

工具：Pineapple
![[pineapple.png]]
airbase-ng
```
airmon-ng start wlan0 #网卡设为monitor模式 
airbase-ng -c 6 -P -C 20 -v mon0 
-c channel 
-v be verbose 
-P (karma mode) respond to all probes. 
-C enables beaconing of probed ESSID values (requires -P)
```
## 缓解
厂商使用不带ssid的扫描方式
![[不带ssid扫描.png]]
iPhone大概在iOS7做了这个改变。Android大概在Android 4.x，还有同样使用了wpa_supplicant的Linux。
查看标设备以前连接过哪些热点”这种需求已基本没法实现。
##  Mana
在2014年的Defcon 22上，由Dominic White 和 Ian de Villiers 发布了mana。mana可以理解为karma 2.0，它针对前文提到的问题做了一些改进：

1.  收集周围空间的SSID信息（来自于老设备的Directed Probe）或者用户自定义。当接收到Broadcast Probe Request时，mana会根据列表中的每一个SSID构造成 Probe Response向客户端回复。
    
客户端在面对同一MAC有多个不同SSID时不会产生问题
    
2.  针对iOS对Hidden SSID的处理，mana会自动创建一个隐藏热点用于触发iOS设备发Directed Probe Request
    
3.  增加了伪造PEAP等EAP SSL方案的热点功能，可以抓取并破解EAP hash。破解后将认证信息存入radius服务器，客户端下次重连就能成功连接了。
    

对Broadcast Probe的解决方案就是通过手动指定常见或自动收集周边的开放式热点信息（城市、机场、公司、超商等公共WiFi）以期望覆盖到客户端曾经连接过的热点。
![[Pasted image 20220607171208.png]]
### 总结
最后总结一下，在如今，吸引客户端连入恶意热点的办法有：

1.  对于老旧的移动设备和笔记本，Karma依然可用，客户端自动连接。
2.  由于隐藏热点的特性，连接依赖于Directed Probe，Karma依然可用（记得创建隐藏热点触发客户端发送），客户端自动连接。
3.  根据周边热点及常见公共热点构造SSID列表进行伪造（比如CMCC、StarBucks等），如果覆盖到客户端曾经连接过的热点，也会自动连接。
4.  伪造PEAP热点获取hash，破解后存入radius服务器，客户端下次重连便能成功。
5.  伪造公共热点，用户受骗主动点击发起连接。