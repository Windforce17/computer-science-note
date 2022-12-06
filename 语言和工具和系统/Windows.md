# win11
## 绕过安全启动，TPM模块检查
在安装界面使用shift+f10打开命令行，然后使用regedit打开注册表
注册表下创建 `HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig`
增加两项DWORD：
`BypassSecureBootCheck 1`
`BypassTPMCheck 1`

## 绕过联网认证
安装完系统后不联网无法点击下一步，使用shift+f10打开命令行,输入`OOBE\BYPASSNRO` 回车即可。