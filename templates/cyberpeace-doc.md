# <center> <%* 
    let name=tp.file.folder().split('_')[1];
    tR+=name
    
  %> </center>

## 【目的】

让学员通过该系统的练习主要掌握：

- <%* 
    tR+=name
  %>
<% tp.file.cursor() %>

## 【环境】

操作机： Ubuntu 20.04

## 【工具】

- Linux
- gcc
- make
- dmesg
- vim

## 【原理】

<% tp.file.cursor() %>

## 【步骤】

1. 进入`linux_driver/<% tp.file.cursor() %>` 查看`lkm.c`

2. 编译并运行模块

<% tp.file.cursor() %>


## 【总结】


通过本实验学习，要求学员掌握<%* tR+=name %>
<% tp.file.cursor() %>
<%*
   let current_path= tp.file.folder(true);
   await this.app.vault.createFolder(current_path+"/doc");
   %>
<% tp.file.move(current_path+"/doc/指导书") %>
   