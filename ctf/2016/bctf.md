# misc

## catvideo
#todo 
bctf-2016-catvideo
ffmpeg.exe -i catvideo-497570b7e2811eb52dd75bac9839f19d7bca5ef4.mp4 -r 30.0 fr_%4d.bmp
```python
from PIL import Image
from PIL import ImageChops

import glob
im0 = Image.open("fr_0001.bmp")

for frame in glob.glob("./frames/*"):
	ImageChops.subtrat(Image.open(frame), im0).save(frame.replace("frames", "frames_new"))

```
ffmpeg -i cat_video.mp4 -r 1/1 stego/$filename%03d.jpg
```shell
for i in `seq 2 9`; do convert stego/00$(expr $i - 1).jpg stego/00$i.jpg -fx "(((255u)&(255(1-v)))|((255(1-u))&(255v)))/255" noncover/00$i.jpg; done
```
Flag: BCTF{cute&fat_cats_does_not_like_drinking}o