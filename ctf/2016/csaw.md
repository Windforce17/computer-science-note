# misc
## watchword
使用exiftool可以看到
```
Artist                          : Stefan Hetzl
Title                           : aHR0cDovL3N0ZWdoaWRlLnNvdXJjZWZvcmdlLm5ldC8=
```
提示了使用steghid，但是这个工具往往针对jpg
使用`foremost powpow.mp4` 得道png
这个png是属于lsb隐写，但是有每字节后9bit是无用的。
```
ff6c3fdc00008128 8c49230000202000  .l?....( .I#..  .
0002000080000ff6 d8008600048180e0  ........ ........
8038181208040201 40a0482c1c170783  .8...... @.H,....
81a0d07070281508 85c441e1188c421e  ...pp(.. ..A...B.
100804a2a1a8b44a 27190a04020170fc  .......J '.....p.
...
真正的jpg头
111111110110110000111111110111000000000000000...
|  FF  | |  D8  | |  FF  | |  E0  | |  00  | ...
```
使用脚本提取出jpg
```python
from PIL import Image
import sys

def b2a(b):
    s = b''
    while len(b) != 0:
        binbyte = b[:8]  # Get a byte
        s += bytes([(int(binbyte, 2))]) # Convert it
        b = b[9:]  # Skip every 9th bit
    return s

# Load image data
img = Image.open(sys.argv[1])
w,h = img.size
pixels = img.load()

binary = ''
for y in range(h):
    for x in range(w):
        # Pull out the LSBs of this pixel in RGB order
        binary += ''.join([str(n & 1) for n in pixels[x, y]])
with open("1.jpg","wb")as f:
   f.write(b2a(binary))
pwn@ubuntu:/mnt/hgfs/sha
```
最后使用`steghide extract -sf img2.jpg -p password` ，得到一个base85解密的字符串。
password是弱口令。
```shell
$ python3
>>> import base64
>>> base64.b85decode('W^7?+dsk&3VRB_4W^-?2X=QYIEFgDfAYpQ4AZBT9VQg%9AZBu9Wh@|fWgua4Wgup0ZeeU}c_3kTVQXa}eE')
flag{We are fsociety, we are finally free, we are finally awake!}
```