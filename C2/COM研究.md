# COM
com程序一般是dll文件，被提供给主程序调用。不同的com程序具有不同的接口，但是所有的接口都是从class factory 和 IUnknown接口获得的。所以com程序必须实现 class factory 和 Iunknown接口
IUnKnown接口
所有COM接口都继承自IUnKnown接口，该接口具有3个成员函数，QueryInterface、IUnknown::QueryInterface和IClassFactory始终贯穿在com组件的调用中。AddRef、Release. 
CoCreateInstance 函数创建com实例并返回客户端请求的接口指针。客户端指的是将CLSID传递给系统并请求com对象实例的调用方
com服务器需要提供 IClassFactory 接口的实现，而且 IClassFactory 包含 CreateInstance方法
在注册com服务器的时候，如果是进程内注册，即dll，dll必须导出以下函数
DllRegisterServer
DllUnregisterServer
几乎所有的COM函数和接口方法都返回HRESULT类型的值，但HRESULT不是句柄
com调用需要的值
1.CLSID
2.IID
3.虚函数表
4.方法签名

整理以后制作IDL，获取到IDL之后，就可以使用合适的语言进行调用


# 注册表关系
```
HKEY_CLASSES_ROOT 用于存储一些文档类型、类、类的关联属性
HKEY_CURRENT_CONFIG 用户存储有关本地计算机系统的当前硬件配置文件信息
HKEY_CURRENT_USER 用于存储当前用户配置项
HKEY_CURRENT_USER_LOCAL_SETTINGS 用于存储当前用户对计算机的配置项
HKEY_LOCAL_MACHINE 用于存储当前用户物理状态
HKEY_USERS 用于存储新用户的默认配置项
```