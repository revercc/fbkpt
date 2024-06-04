# fbkpt
`fbkpt`是一个`frida`脚本，它可以实现对app native层代码设置软件断点和内存读写断点
## 软件断点
软件断点是基于`bkpt`指令（64位是brk)，通过修改目标地址的指令为`bkpt`并设置异常处理程序来处理断点异常。

1. 软件断点的持久化：把目标地址修改为`bkpt`之前需要将原始指令保存，在断点触发的时候需要执行原始指令，如果将原始指令copy回原地址就需要考虑到执行完原始指令后恢复断点。在`x86`平台上可以借助单步异常（硬件单步）来实现，也就是原始指令执行后会触发单步异常，并在单步异常处理程序中恢复软件断点。但是`arm`平台并不支持硬件单步，但是可以借助软件单步来实现，软件单步就是在原始指令的下一条指令处设置一次性软件断点，这就需要解析原始指令的下一条指令的地址（较麻烦，暂未实现）。因为考虑到在设置软件断点的时候只是对一些简单的指令下断点，所以可以自己手动模拟原始指令的行为，这样就不需要将原始指令copy回去从而实现断点持久化。（目前只实现了`blx`和`blr`）
2. 一次性软件断点：一次性软件断点就是在软件断点第一被触发的时候将原始指令恢复

参数
1. `module_address`是目标地址所在的模块地址
2. `target_address`是需要设置断点的目标地址
3. `is_thumb`指令是否为`thumb`模式
4. `is_64bit`指令是否为64位模式
5. `is_one_only`是否设置一次性软件断点
```
set_native_bkpt(module_address, target_address, is_thumb, is_64bit, is_one_only)
```

## 内存读写断点
内存读写断点是基于内存访问异常实现的，通过修改目标地址所在的内存页属性并设置异常处理程序来捕获访问内存的操作。
1. 内存读写断点的持久化：因为当内存读写异常触发的时候修改将目标内存地址所在的内存页属性恢复，所以涉及到再次恢复内存读写断点的问题，因为内存访问指令一般不涉及到跳转的问题，所以其下一条指令的地址就是当前地址 + 自身指令大小，所以就通过对下一条指令设置一次性软件断点来将内存读写断点恢复（软件单步）。`frida`官方提供的就是一次性的内存读写断点接口`MemoryAccessMonitor`，并不能进行持久化
2. 内存读写断点的粒度：因为是通过修改内存页属性实现的，所以目标地址所在的内存页上的任意地址被访问的时候都会触发内存读写断点，不过这里只对命中了内存读写断点范围的内存访问指令进行详细打印


参数
1. `page_base`是目标地址所在的页基地址
2. `target_address`是需要设置内存读写断点的目标地址
3. `size`是内存读写断点的范围
```
set_read_memory_bkpt(page_base, target_address, size)
```