var is_thumb = 0
var is_arm64 = 0
const global_bkpt_maps = new Map()

const global_memory_bkpt_maps = new Map()

const malloc = new NativeFunction(Module.findExportByName('libc.so', 'malloc'), 'pointer', ['size_t']);
const memset = new NativeFunction(Module.findExportByName('libc.so', 'memset'), 'pointer', ['pointer', 'size_t', 'int']);
const mprotect = new NativeFunction(Module.findExportByName('libc.so', 'mprotect'), 'int', ['pointer', 'size_t', 'int']);
const free = new NativeFunction(Module.findExportByName('libc.so', 'free'), 'void', ['pointer']);
const PROT_NONE = 0
const PROT_READ = 1
const PROT_WRITE = 2
const PROT_EXEC = 3

function print64_regs(context){
    console.log("x0 : ", context.x0.toString(), " ", "x1 : ", context.x1.toString(), " ", "x2 : ", context.x2.toString(), " ",
    "x3 : ", context.x3.toString(), " ", "x4 : ", context.x4.toString(), " ", "x5 : ", context.x5.toString(), " ",
    "x6 : ", context.x6.toString(), " ", "x7 : ", context.x7.toString(), " ", "x8 : ", context.x8.toString(), " ", 
    "x9 : ", context.x9.toString(), " ", "x10 : ", context.x10.toString(), " ", "x11 : ", context.x11.toString(), " ", 
    "x12 : ", context.x12.toString(), " ", "x13 : ", context.x13.toString(), " ", "x14 : ", context.x14.toString(), " ", 
    "x15 : ", context.x15.toString(), " ", "x16 : ", context.x16.toString(), " ", "x17 : ", context.x17.toString(), " ", 
    "x18 : ", context.x18.toString(), " ", "x19 : ", context.x19.toString(), " ", "x20 : ", context.x20.toString(), " ", 
    "x21 : ", context.x21.toString(), " ", "x22 : ", context.x22.toString(), " ", "x23 : ", context.x23.toString(), " ", 
    "x24 : ", context.x24.toString(), " ", "x25 : ", context.x25.toString(), " ", "x26 : ", context.x26.toString(), " ", 
    "x27 : ", context.x27.toString(), " ", "x28 : ", context.x28.toString(), " ", "x29 : ", context.fp.toString(), " ",
    "x30 : ", context.lr.toString())
}

function print32_regs(context){
    console.log("r0 : ", context.r0.toString(), " ", "r1 : ", context.r1.toString(), " ", "r2 : ", context.r2.toString(), " ",
    "r3 : ", context.r3.toString(), " ", "r4 : ", context.r4.toString(), " ", "r5 : ", context.r5.toString(), " ",
    "r6 : ", context.r6.toString(), " ", "r7 : ", context.r7.toString(), " ", "r8 : ", context.r8.toString(), " ", 
    "r9 : ", context.r9.toString(), " ", "r10 : ", context.r10.toString(), " ", "r11 : ", context.r11.toString(), " ", 
    "r12 : ", context.r12.toString(), " ", "r13 : ", context.r13.toString(), " ", "r14 : ", context.r14.toString(), " ", 
    "r15 : ", context.r15.toString())
}

function my_hander(details){
    if(details.type == 'breakpoint'){
        var bkpt_info = global_bkpt_maps.get(details.address.toString(16))
        if(bkpt_info == undefined){
            return false
        }

        // get old_bytes
        var old_bytes_ptr = Memory.alloc(0x4)
        old_bytes_ptr.writeU32(bkpt_info.old_bytes)

        // parse instruction
        var ins
        if(bkpt_info.ins_type.match("thumb")){
            ins = Instruction.parse(old_bytes_ptr.add(1))
        }
        else{
            ins = Instruction.parse(old_bytes_ptr)
        }

        // 判断是否是一次性断点，用来恢复内存断点
        if(bkpt_info.is_one_only){
            // 遍历内存断点并将需要reset的恢复
            global_bkpt_maps.forEach(function(key, val){
                if(val.is_wait_reset){
                    // read memory bkpt
                    if(val.type == 0){
                        set_read_memory_bkpt(parseInt(val.page_base, 16), parseInt(val.base, 10), val.size)
                    }
                    // write memory bkpt
                    else if(val.type == 1){
                        set_write_memory_bkpt(parseInt(val.page_base, 16), parseInt(val.base, 10), val.size)
                    }
                }
            })

            // 将一次性的断点恢复继续执行
            Memory.writeByteArray(details.context.pc, old_bytes_ptr.readByteArray(4))
            console.log("\n")
            return true
        }

        console.log('details.address : ', details.address)
        console.log('details.type : ', details.type)
        console.log("ins : ", ins)

        // simulate exec ins
        switch(ins.mnemonic){
            case "blr":
            case "blx":
                // simulate exec : blx reg / blr reg
                if(ins.operands.length == 1 && ins.operands[0].type.match("reg")){              
                    console.log(ins.operands[0].value, " : ", details.context[ins.operands[0].value])
                    console.log("blx   ", (details.context[ins.operands[0].value] - parseInt(bkpt_info.module_base, 16)).toString(16))
                    details.context.lr = details.context.pc.add(ins.size)
                    if(bkpt_info.ins_type.match("thumb")){
                        details.context.lr = details.context.lr.add(1)
                    }
                    details.context.pc = details.context[ins.operands[0].value]
                }
                // simulate exec : blx imm 
                else if(ins.operands.length == 1 && ins.operands[0].type.match("imm")){
                    console.log("blx   ", ins.operands[0].value)
                    details.context.lr = details.context.pc.add(ins.size)
                    if(bkpt_info.ins_type.match("thumb")){
                        details.context.lr = details.context.lr.add(1)
                    }
                    details.context.pc = parseInt(bkpt_info.module_base, 16) + ins.operands[0].value
                }
                break
            default:
                console.log("not support this instruction to set breakpoint !")
                break
        }
        console.log("\n")
        return true
    }
    else if(details.type == 'access-violation'){
        console.log('pc : ', details.context.pc)
        console.log('details.type : ', details.type)

        var access_page_base = ptr(details.memory.address.shr(12).shl(12))
        var access_addr = ptr(details.memory.address)
        global_memory_bkpt_maps.forEach(function(key, val){
            if (access_addr >= ptr(parseInt(val.page_base, 16))  &&
                access_addr <= ptr(parseInt(val.page_base, 16)).add(val.page_size * 0x1000)){
                access_page_base = ptr(parseInt(val.page_base, 16))
            }
        })

        var memory_bkpt_info = global_memory_bkpt_maps.get(access_page_base.toString(16))
        if(memory_bkpt_info == undefined){
            console.log("unknown memory access exception")
            return false
        }

        // change memory property to old (default rwx)
        mprotect(ptr(parseInt(memory_bkpt_info.page_base, 16)), memory_bkpt_info.page_size * 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC)

        // set one only bkpt to reset memory bkpt 
        memory_bkpt_info.is_wait_reset = 1
        global_memory_bkpt_maps.set(memory_bkpt_info.page_base, memory_bkpt_info)
        
        var ins
        if(is_thumb){
            ins = Instruction.parse(details.context.pc.add(1))
        }
        else{
            ins = Instruction.parse(details.context.pc)
        }

        var module_base = 0
        var module_array = Process.enumerateModules()
        for(var i = 0; i < module_array.length; i++){
            if (details.context.pc >= module_array[i].base &&
                details.context.pc <= (module_array[i].base.add(module_array[i].size))){
                    module_base =  module_array[i].base
                    break
            }
            
        }
        set_native_bkpt(module_base, details.context.pc.add(ins.size), is_thumb, is_arm64, 1)

        var target_address = ptr(memory_bkpt_info.base)
        if (access_addr >= target_address &&
            access_addr <= target_address.add(memory_bkpt_info.size)){
            console.log("access addr is : ", access_addr)
            console.log("ins : ", ins)
            if(is_arm64){
                print64_regs(details.context)
            }
            else{
                print32_regs(details.context)
            }
        }
        console.log("\n")
        return true
    }
}

// 设置读内存断点
function set_read_memory_bkpt(page_base, target_address, size){

    const memory_bkpt_info = {
        base : "",
        size : 0,
        page_base : "",
        page_size : 0,
        is_one_only : 0,
        is_wait_reset : 0,
        type : 0
    }

    // change target_address memory 
    page_base = new NativePointer(page_base)
    target_address = new NativePointer(target_address)
    console.log("call mprotect : ", target_address, " ", page_base)
    var page_size 
    if(target_address.add(size).sub(page_base) % 0x1000) {
        page_size = target_address.add(size).sub(page_base).shr(12).shl(12) + 1
    }else{
        page_size = target_address.add(size).sub(page_base).shr(12).shl(12)
    }
    var ret = mprotect(page_base, page_size * 0x1000, PROT_NONE)
    memory_bkpt_info.base = target_address.toString()
    memory_bkpt_info.size = size
    memory_bkpt_info.type = 1
    memory_bkpt_info.page_base = page_base.toString(16)
    memory_bkpt_info.page_size = page_size

    // set signal handler
    Process.setExceptionHandler(my_hander)

    // add global memory bkpt maps
    global_memory_bkpt_maps.set(page_base.toString(16), memory_bkpt_info)
}

// 设置写内存断点
function set_write_memory_bkpt(page_base, target_address, size){

    const memory_bkpt_info = {
        base : "",
        size : 0,
        page_base : "",
        is_one_only : 0,
        is_wait_reset : 0,
        type : 1
    }
    
    // change target_address memory 
    page_base = new NativePointer(page_base)
    target_address = new NativePointer(target_address)
    var page_size 
    if(target_address.add(size).sub(page_base) % 0x1000) {
        page_size = target_address.add(size).sub(page_base).shr(12).shl(12) + 1
    }else{
        page_size = target_address.add(size).sub(page_base).shr(12).shl(12)
    }
    var ret = mprotect(page_base, page_size * 0x1000, PROT_NONE)
    memory_bkpt_info.base = target_address.toString()
    memory_bkpt_info.size = size
    memory_bkpt_info.type = 1
    memory_bkpt_info.page_base = page_base.toString(16)
    memory_bkpt_info.page_size = page_size

    // set signal handler
    Process.setExceptionHandler(my_hander)

    // add global memory bkpt maps
    global_memory_bkpt_maps.set(page_base.toString(16), memory_bkpt_info)
}

// 设置软件断点
function set_native_bkpt(module_address, target_address, is_thumb, is_64bit, is_one_only){

    const bkpt_info = {
        module_base : "",
        old_bytes : 0, 
        is_one_only : 0,
        ins_type : ""
    }

    bkpt_info.is_one_only = is_one_only
    module_address = new NativePointer(module_address)
    target_address = new NativePointer(target_address)
    bkpt_info.module_base = module_address.toString(16)
    if(undefined != global_bkpt_maps.get(target_address.toString(16))){
        console.log("breakpoint is exits !")
        return
    }
    
    if(!Memory.protect(target_address, 4, 'rwx')){
        console.log("target_address memory changne rwx false")
        return
    }
    
    // copy old bytes and patch breakpoint
    if(is_thumb){
        bkpt_info.ins_type = "thumb"
        bkpt_info.old_bytes = target_address.readU16()
        // thumb : 00be (bkpt) 
        Memory.writeByteArray(target_address, [0x00, 0xbe])
    }
    else if(!is_64bit){
        bkpt_info.ins_type = "arm32"
        bkpt_info.old_bytes = target_address.readU32()
        // arm   : 700020E1 (bkpt)
        Memory.writeByteArray(target_address, [0x70, 0x00, 0x20, 0xe1])
    }
    else{
        bkpt_info.ins_type = "arm64"
        bkpt_info.old_bytes = target_address.readU32()
        // arm64 : 002020D4 (brk 0x100)
        Memory.writeByteArray(target_address, [0x00, 0x20, 0x20, 0xd4])
    }

    // set signal handler
    Process.setExceptionHandler(my_hander)

    // add global bkpt maps
    global_bkpt_maps.set(target_address.toString(16), bkpt_info)
}

function hook_target_so(){
    is_thumb = 0
    is_arm64 = 1
    var target_address = 0x12345678
    var page_base = 0x12345000
    set_write_memory_bkpt(page_base, target_address, 0x20)
}