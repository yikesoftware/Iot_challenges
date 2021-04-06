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

## Protocol
