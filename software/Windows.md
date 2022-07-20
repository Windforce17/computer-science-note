# win11 安装绕过TPM检查
安装时按下shift+f10打开控制台，输入`regedit`打开注册表编辑器
`HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig\BypassTPMCheck` 设置为1，类型为DWORD。
# 激活
使用pykms服务器:https://github.com/Py-KMS-Organization/py-kms

# caps2ctrl
```powershell
$hexified = "00,00,00,00,00,00,00,00,02,00,00,00,1d,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"};

$kbLayout = 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout';

New-ItemProperty -Path $kbLayout -Name "Scancode Map" -PropertyType Binary -Value ([byte[]]$hexified);

```