## Iot Challenges

题目摘要格式：

```sh
## 类别

No. [赛事] 题目
    - 摘要1
    - 摘要2
    ... 
```

## Httpd

1. [qwb] gamebox
   
   - `mips64`架构，大端续，`uClib`运行库
   - `error_request`中向堆缓冲区`memcpy`拷贝发生错误的参数内容时超长，存在堆溢出
   - `uClib`下堆利用，类似早期的`dlmalloc`，fastbin伪造不检查大小
   - 没有`__free_hook`或`__malloc_hook`，但libc中函数间调用通过got表
   - `free`函数检查chunk大小和标志位满足特定条件时会调用`munmap`，可以借此调用`system`getshell

2. [qwb] xx_easy_server

   - x86架构
   - Location拼接过长，导致整数溢出，栈上越界写
   - 溢出后需要EOF截断输入，不能leak，需要结合已知地址构造rop
   - 单字符拼接文件名，栈迁移调用`do_file`实现任意文件读
   
3. [RWCTF] Game2048

   分析：
   - 使用了协程库，可以并行处理多个HTTP请求
   - 堆的UAF漏洞发生在submit的处理逻辑中，进入submit时会先尝试free之前的comment，但不立刻置NULL
   - 但是在修改同一个用户的comment时，如果前一个请求阻塞在`AIO::read`，则后一个请求会把同一个comment指针再free一次。然而这不会直接`double free`，因为这部分内存会被别的结构占住。
   - `submit_page`里面会输出comment的内容，造成地址泄漏。
   
   利用：
   - 泄漏出libc地址
   - 请求A：free一个comment然后阻塞在`AIO::read`处
   - 请求B：对同一个用户的comment再次free
   - 继续完成请求A，此时会凑巧在`tcache`上出现一个loop chain
   - 请求C：尝试修改fd即可指向`__free_hook-0x10` (C++对象创建和销毁操作比较多，不当的操作很容易crash，只能慢慢试)
   - 请求D：同样进入`AIO::read`的逻辑，借助一个合适大小的buffer拿到`__free_hook-0x10`，写入参数和`system`地址
   - 当请求D被完成，buffer被free后就可以getshell了
   
4. [qwb] qwbhttpd

   分析&利用：
   - 博客：[[强网杯 Final 2021] 固件题 qwbhttpd 解题思路](https://eqqie.cn/index.php/laji_note/1694/)

## Protocol
