# COM
com程序一般是dll文件，被提供给主程序调用。不同的com程序具有不同的接口，但是所有的接口都是从class factory 和 IUnknown接口获得的。所以com程序必须实现 class factory 和 Iunknown接口
IUnKnown接口
所有COM接口都继承自IUnKnown接口，该接口具有3个成员函数，QueryInterface、AddRef、Release. 
CoCreateInstance 函数创建com实例并返回客户端请求的接口指针。客户端指的是将CLSID传递给系统并请求com对象实例的调用方


# 注册表关系
```
HKEY_CLASSES_ROOT 用于存储一些文档类型、类、类的关联属性
HKEY_CURRENT_CONFIG 用户存储有关本地计算机系统的当前硬件配置文件信息
HKEY_CURRENT_USER 用于存储当前用户配置项
HKEY_CURRENT_USER_LOCAL_SETTINGS 用于存储当前用户对计算机的配置项
HKEY_LOCAL_MACHINE 用于存储当前用户物理状态
HKEY_USERS 用于存储新用户的默认配置项
```