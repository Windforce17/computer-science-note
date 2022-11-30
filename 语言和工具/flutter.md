# 资料
https://github.com/flutterchina/flutter_in_action_2nd
https://book.flutterchina.club/
https://github.com/OpenFlutter/Flutter-Notebook
https://github.com/nisrulz/flutter-examples
https://github.com/alibaba/flutter-go
# 常见概念
## 路由
Material包里自带一个路由管理，支持命名路由等。
通过使用Navigator可以控制页面路由跳转，还会生成一个返回的箭头在左上角。
```dart
onPressed: () {
        //导航到新路由   
        Navigator.push( 
          context,
          MaterialPageRoute(builder: (context) {
            return NewRoute();
          }),
```
## 状态管理
全局、父管理子，混合，都可以，看怎么写了。
```dart
// ParentWidget 为 TapboxB 管理状态.

//------------------------ ParentWidget --------------------------------

class ParentWidget extends StatefulWidget {
  @override
  _ParentWidgetState createState() => _ParentWidgetState();
}

class _ParentWidgetState extends State<ParentWidget> {
  bool _active = false;

  void _handleTapboxChanged(bool newValue) {
    setState(() {
      _active = newValue;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      child: TapboxB(
        active: _active,
        onChanged: _handleTapboxChanged,
      ),
    );
  }
}

//------------------------- TapboxB ----------------------------------

class TapboxB extends StatelessWidget {
  TapboxB({Key? key, this.active: false, required this.onChanged})
      : super(key: key);

  final bool active;
  final ValueChanged<bool> onChanged;

  void _handleTap() {
    onChanged(!active);
  }

  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: _handleTap,
      child: Container(
        child: Center(
          child: Text(
            active ? 'Active' : 'Inactive',
            style: TextStyle(fontSize: 32.0, color: Colors.white),
          ),
        ),
        width: 200.0,
        height: 200.0,
        decoration: BoxDecoration(
          color: active ? Colors.lightGreen[700] : Colors.grey[600],
        ),
      ),
    );
  }
}
```

## 组件
文本、按钮、图片、复选框、输入框、表单、进度条..
## 布局
## material 颜色
```dart
Map<int, Color> color =
{
50:Color.fromRGBO(136,14,79, .1),
100:Color.fromRGBO(136,14,79, .2),
200:Color.fromRGBO(136,14,79, .3),
300:Color.fromRGBO(136,14,79, .4),
400:Color.fromRGBO(136,14,79, .5),
500:Color.fromRGBO(136,14,79, .6),
600:Color.fromRGBO(136,14,79, .7),
700:Color.fromRGBO(136,14,79, .8),
800:Color.fromRGBO(136,14,79, .9),
900:Color.fromRGBO(136,14,79, 1),
};
```
# 命令
1. 不安装Chrome开web服务器： flutter run -d web-server --debug
2. 装一个flutter调试工具可以看到不同的wiget状态