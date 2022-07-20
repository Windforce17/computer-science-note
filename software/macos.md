# 开放nat网络共享
```
sysctl -w net.inet.ip.forwarding=1
```

pf.conf:

```
nat on en0 from 10.0.0.1/24 to any -> (en0)
```

-   禁用pf：`sudo pfctl -d`
-   清空所有规则： `sudo pfctl -F all`
-   应用规则并启动：`sudo pfctl -f /Path/to/file/pf-nat.conf -e`

# 禁用.DS_Stroe
```sh
defaults write com.apple.desktopservices DSDontWriteNetworkStores true
find ~ -name .DS_Store -delete
```

# 字体启用
vscode:
'CaskaydiaCove Nerd Font'