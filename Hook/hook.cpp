#include "hook.h"
#include <stdio.h>
#include "capstone/x86.h"
#include "capstone/capstone.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

// using namespace hook;
namespace hook {

void* alloc_page_near_address(void* target_addr) {
    static int64_t pageSize = getpagesize();
    size_t length = pageSize;
    int prot = PROT_READ | PROT_WRITE; // 内存保护标志，允许读写
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED; // 映射标志，指定了 MAP_FIXED
    int fd = -1; // 没有文件描述符
    off_t offset = 0; // 没有文件偏移量

    void *ptr = mmap(target_addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return nullptr;
    }
    printf("Mapped memory at address: %p\n", ptr);
    return ptr;
}

// void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
// {
//     uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                       0x41, 0xFF, 0xE2 };

//     uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
//     memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
//     memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
// }

struct X64Instructions {
    cs_insn* instructions;
    uint32_t numInstructions;
    uint32_t numBytes;
};

X64Instructions StealBytes(void* function) {
    // static int64_t page_size = getpagesize();
    // // get the start address of the page containing the function
    // uintptr_t page_start = ((uintptr_t)function) & (~(page_size - 1));

    // // set the memory protections to read/write/execute, so that we can modify the instructions
    // if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    //     perror("mprotect");
    // }

    // Disassemble stolen bytes
    std::cout << "Stealing bytes from: " << function << std::endl;
    csh handle;
    auto s = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (s != 0) {
        std::cout << "Error opening capstone handle" << std::endl;
    }
    s = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // we need details enabled for relocating RIP relative instrs
    if (s != 0) {
        std::cout << "Error set option" << std::endl;
    }

    // for cpu with BIT check, the first instruction of a function is endbr
    // endbr64 instruction: 0xfa1e0ff3
    uint32_t endbr64 = 0xfa1e0ff3;
    uint8_t* code = (uint8_t*)function; 
    if (endbr64 == *(uint32_t*)function) {
        code = (uint8_t*)function + 4;
    }

    size_t count;
    cs_insn* disassembledInstructions; //allocated by cs_disasm, needs to be manually freed later
    count = cs_disasm(handle, code, 20, (uint64_t)code, 20, &disassembledInstructions);
    if (count == 0) {
        s = cs_errno(handle);
        std::cout << "error status: " << cs_strerror(s) << std::endl;
    }

    // get the instructions covered by the first 9 bytes of the original function
    uint32_t byteCount = 0;
    uint32_t stolenInstrCount = 0;
    for (int32_t i = 0; i < count; ++i) {
        cs_insn& inst = disassembledInstructions[i];
        byteCount += inst.size;
        stolenInstrCount++;
        if (byteCount >= 9) break;
    }

    std::cout << "byteCount: " << byteCount << std::endl;
    std::cout << std::hex << (void*)code << std::endl;
    //replace instructions in target func wtih NOPs
    memset((void*)code, 0x90, byteCount);

    cs_close(&handle);
    return { disassembledInstructions, stolenInstrCount, byteCount };
}


void enable_mem_write(void* func) {
    static int64_t page_size = getpagesize();

    // get the start address of the page containing the function
    uintptr_t page_start = ((uintptr_t)func) & (~(page_size - 1));

    // set the memory protections to read/write/execute, so that we can modify the instructions
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
    }
}

void write_absolute_jump64(void* relay_func_mem, void* jmp_target) {
    uint8_t abs_jmp_instrs[] = {
        0xf3, 0x0f, 0x1e, 0xfa,
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE2 };

    uint64_t jump_target_addr = (uint64_t)jmp_target;
    memcpy(&abs_jmp_instrs[6], &jump_target_addr, sizeof(jump_target_addr));
    memcpy(relay_func_mem, abs_jmp_instrs, sizeof(abs_jmp_instrs));
}

int64_t build_trampoline(void* func2hook, void* dstMemForTrampoline) {
    X64Instructions stolenInstrs = StealBytes(func2hook);

    uint8_t* stolenByteMem = (uint8_t*)dstMemForTrampoline;
    uint8_t* jumpBackMem = stolenByteMem + stolenInstrs.numBytes;
    uint8_t* absTableMem = jumpBackMem + 13; //13 is the size of a 64 bit mov/jmp instruction pair

    for (uint32_t i = 0; i < stolenInstrs.numInstructions; ++i)
    {
        cs_insn& inst = stolenInstrs.instructions[i];
        if (inst.id >= X86_INS_LOOP && inst.id <= X86_INS_LOOPNE)
        {
            return 0; //bail out on loop instructions, I don't have a good way of handling them 
        }

        // if (IsRIPRelativeInstr(inst))
        // {
        //     RelocateInstruction(&inst, stolenByteMem);
        // }
        // else if (IsRelativeJump(inst))
        // {
        //     uint32_t aitSize = AddJmpToAbsTable(inst, absTableMem);
        //     RewriteJumpInstruction(&inst, stolenByteMem, absTableMem);
        //     absTableMem += aitSize;
        // }
        // else if (inst.id == X86_INS_CALL)
        // {
        //     uint32_t aitSize = AddCallToAbsTable(inst, absTableMem, jumpBackMem);
        //     RewriteCallInstruction(&inst, stolenByteMem, absTableMem);
        //     absTableMem += aitSize;
        // }
        memcpy(stolenByteMem, inst.bytes, inst.size);
        stolenByteMem += inst.size;
    }

    // WriteAbsoluteJump64(jumpBackMem, (uint8_t*)func2hook + 5);
    // free(stolenInstrs.instructions);

    return uint32_t(absTableMem - (uint8_t*)dstMemForTrampoline);
}


void print_first_inst(void* func) {
    enable_mem_write(func);
    X64Instructions insts = StealBytes(func);
    int64_t inst_num = insts.numInstructions;
    std::cout << "First inst num: " << inst_num << std::endl;
    for (int64_t i = 0; i < inst_num; ++i) {
        cs_insn& inst = insts.instructions[i];
        std::cout << i << "st inst: " << std::endl;
        std::cout << inst.op_str << std::endl;
    }
}

void instal_hook(void* hooked_func, void* payload_fuc, void** trampoline_ptr) {
    enable_mem_write(hooked_func);
    void* hook_memory =  alloc_page_near_address(hooked_func);
    int64_t trampoline_size = build_trampoline(hooked_func, hook_memory);
    *trampoline_ptr = hook_memory;

    // create relay function
    void* relay_func_mem = (u_int8_t*)hook_memory + trampoline_size;
    write_absolute_jump64(relay_func_mem, payload_fuc);

    uint8_t jmp_instrs[9] = { 0xE9, 0x0, 0x0, 0x0, 0x0, 0xf3, 0x0f, 0x1e, 0xfa };
    const uint64_t relative_addr = (uint64_t)relay_func_mem - ((uint64_t)hooked_func + sizeof(jmp_instrs));
    if (relative_addr > UINT32_MAX) {
        std::cout << "Error: relative address is larger than UINT32_MAX" << std::endl;
    }
    const uint32_t relative_addr_u32 = (uint32_t)relative_addr;
    memcpy(jmp_instrs + 1, &relative_addr_u32, sizeof(uint32_t));
    memcpy(((uint8_t*)hooked_func) + 4, jmp_instrs, sizeof(jmp_instrs));
}

}   // namespace hook