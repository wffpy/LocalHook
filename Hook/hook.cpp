#include "hook.h"

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>

#include "capstone/capstone.h"
#include "capstone/x86.h"

// using namespace hook;
namespace hook {

void *alloc_page_near_address(void *target_addr) {
    std::cout << "alloc_page_near_address: " << target_addr << std::endl;
    static int64_t page_size = getpagesize();
    size_t length = page_size;
    int prot = PROT_READ | PROT_WRITE | PROT_EXEC; // 内存保护标志，允许读写
    int flags =
        MAP_FIXED_NOREPLACE | MAP_ANONYMOUS; // 映射标志，指定了 MAP_FIXED
    int fd = -1;                             // 没有文件描述符
    off_t offset = 0;                        // 没有文件偏移量

    uintptr_t start_addr = ((uintptr_t)target_addr) & (~(page_size - 1));
    std::cout << "start_addr: " << std::hex << start_addr << std::endl;
    uint64_t page_start = start_addr - (start_addr % page_size);
    std::cout << "page_start: " << std::hex << page_start << std::endl;
    int64_t bytes_offset = page_size;
    while (1) {
        if (bytes_offset < INT32_MAX) {
            uint64_t address = page_start + bytes_offset;
            std::cout << "address: " << address << std::endl;
            void *ptr = mmap((void *)address, length, prot, flags, fd, offset);
            std::cout << "after mmp" << std::endl;
            if (ptr == MAP_FAILED) {
                perror("mmap");
            } else if (ptr) {
                printf("Mapped memory at address: %p\n", ptr);
                return ptr;
            }
            address = page_start - bytes_offset;
            std::cout << "address: " << address << std::endl;
            ptr = mmap((void *)address, length, prot, flags, fd, offset);
            if (ptr == MAP_FAILED) {
                perror("mmap");
            } else if (ptr) {
                printf("Mapped memory at address: %p\n", ptr);
                return ptr;
            }

            bytes_offset += page_size;
        } else {
            std::cout << "bytes offset is large than INT32_MAX: "
                      << bytes_offset << std::endl;
            exit(0);
        }
    }
    // void *ptr = mmap(target_addr, length, prot, flags, fd, offset);
    // void *ptr = mmap(NULL, length, prot, flags, fd, offset);
    // if (ptr == MAP_FAILED) {
    //     perror("mmap");
    //     return nullptr;
    // }
    // printf("Mapped memory at address: %p\n", ptr);
    return nullptr;
}

// void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
// {
//     uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00,
//                       0x41, 0xFF, 0xE2 };

//     uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
//     memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
//     memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
// }

struct X64Instructions {
    cs_insn *instructions;
    uint32_t numInstructions;
    uint32_t numBytes;
};

X64Instructions StealBytes(void *function) {
    // static int64_t page_size = getpagesize();
    // // get the start address of the page containing the function
    // uintptr_t page_start = ((uintptr_t)function) & (~(page_size - 1));

    // // set the memory protections to read/write/execute, so that we can
    // modify the instructions if (mprotect((void*)page_start, page_size,
    // PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    //     perror("mprotect");
    // }

    // Disassemble stolen bytes
    std::cout << "Stealing bytes from: " << function << std::endl;
    csh handle;
    auto s = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (s != 0) {
        std::cout << "Error opening capstone handle" << std::endl;
    }
    s = cs_option(handle, CS_OPT_DETAIL,
                  CS_OPT_ON); // we need details enabled for relocating RIP
                              // relative instrs
    if (s != 0) {
        std::cout << "Error set option" << std::endl;
    }

    // for cpu with BIT check, the first instruction of a function is endbr
    // endbr64 instruction: 0xfa1e0ff3
    uint32_t endbr64 = 0xfa1e0ff3;
    uint8_t *code = (uint8_t *)function;
    if (endbr64 == *(uint32_t *)function) {
        code = (uint8_t *)function + 4;
    }

    size_t count;
    cs_insn *disassembledInstructions; // allocated by cs_disasm, needs to be
                                       // manually freed later
    count = cs_disasm(handle, code, 20, (uint64_t)code, 20,
                      &disassembledInstructions);
    if (count == 0) {
        s = cs_errno(handle);
        std::cout << "error status: " << cs_strerror(s) << std::endl;
    }

    // get the instructions covered by the first 9 bytes of the original
    // function
    uint32_t byteCount = 0;
    uint32_t stolenInstrCount = 0;
    for (int32_t i = 0; i < count; ++i) {
        cs_insn &inst = disassembledInstructions[i];
        byteCount += inst.size;
        stolenInstrCount++;
        if (byteCount >= 5)
            break;
    }

    std::cout << "byteCount: " << byteCount << std::endl;
    std::cout << std::hex << (void *)code << std::endl;
    // replace instructions in target func wtih NOPs
    memset((void *)code, 0x90, byteCount);

    cs_close(&handle);
    return {disassembledInstructions, stolenInstrCount, byteCount};
}

void enable_mem_write(void *func) {
    static int64_t page_size = getpagesize();

    // get the start address of the page containing the function
    uintptr_t page_start = ((uintptr_t)func) & (~(page_size - 1));

    // set the memory protections to read/write/execute, so that we can modify
    // the instructions
    if (mprotect((void *)page_start, page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
    }
}

void write_absolute_jump64(void *relay_func_mem, void *jmp_target) {
    uint8_t abs_jmp_instrs[] = {0xf3, 0x0f, 0x1e, 0xfa, 0x49, 0xBA,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x41, 0xFF, 0xE2};

    uint64_t jump_target_addr = (uint64_t)jmp_target;
    memcpy(&abs_jmp_instrs[6], &jump_target_addr, sizeof(jump_target_addr));
    memcpy(relay_func_mem, abs_jmp_instrs, sizeof(abs_jmp_instrs));
}

/// @brief
/// @param write_addr
/// @param call_target
/// @return: the bytes of write instructions
uint32_t write_absolute_call64(void *write_addr, void *call_target) {
    uint8_t abs_call_instrs[] = {// 0xf3, 0x0f, 0x1e, 0xfa,
                                 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x41, 0xFF, 0xD2};

    uint64_t call_target_addr = (uint64_t)call_target;
    memcpy(&abs_call_instrs[6], &call_target_addr, sizeof(call_target_addr));
    memcpy(write_addr, abs_call_instrs, sizeof(abs_call_instrs));
    // return 17;
    return 13;
}

// check if the instruction operand is a RIP relative address
bool is_rip_relative_inst(cs_insn &inst) {
    cs_x86 *x86 = &(inst.detail->x86);
    for (uint32_t i = 0; i < x86->op_count; ++i) {
        cs_x86_op *op = &(x86->operands[i]);
        if (op->type == X86_OP_MEM) {
            return op->mem.base == X86_REG_RIP;
        }
    }
    return false;
}

// template<typename T>
// T get_operand_disp(cs_x86_op* x86_op) {
//     return x86_op->mem.disp;
// }

bool check_mem_offset(int64_t offset, int64_t bytes) {
    switch (bytes) {
    case 1: {
        return INT8_MIN < offset < INT8_MAX;
    }
    case 2: {
        return INT16_MIN < offset < INT16_MAX;
    }
    case 3: {
        return INT32_MIN < offset < INT32_MAX;
    }
    default: {
        std::cout << "Unsupported operand size: " << bytes << std::endl;
        exit(0);
        return false;
    }
    }
    return false;
}

/// @brief instruction has been move to a new address,
/// so need to update the operand which is relative address.
/// @param inst
/// @param new_addr
void relocate_instruction(cs_insn *inst, void *new_addr) {
    cs_x86 *x86 = &(inst->detail->x86);
    uint64_t inst_addr = inst->address;
    // 1. traverse the operands of instruction, find the one that is relative
    // address
    for (uint32_t i = 0; i < x86->op_count; ++i) {
        cs_x86_op *op = &(x86->operands[i]);
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
            uint8_t bytes = op->size;
            int64_t disp = op->mem.disp;
            disp -= (int64_t)((uint64_t)new_addr - inst_addr);
            if (!check_mem_offset(disp, bytes)) {
                std::cout << "Invalid displacement: " << disp << std::endl;
                exit(0);
            }
            op->mem.disp = disp;
        }
    }
}

bool is_jump(cs_insn &inst) {
    if (inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS) {
        return true;
    }
    return false;
}

// 1. conditional jump instructions must be relative jump
// 2. uncondition jump: if jump with a relative address, the instruction must
// start with 0xeb or 0xe9
bool is_relative_jump(cs_insn &inst) {
    bool is_any_jump = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
    bool is_jmp = inst.id == X86_INS_JMP;
    bool start_with_eb_or_e9 = inst.bytes[0] == 0xeb || inst.bytes[0] == 0xe9;
    return is_jmp ? start_with_eb_or_e9 : is_any_jump;
}

uint32_t add_jmp_to_abs_table(cs_insn &inst, uint8_t *write_addr) {
    // char* jmp_target_addr = (char*)inst.op_str;
    if (!is_jump(inst)) {
        std::cout << " not a jump instruction: " << inst.mnemonic << std::endl;
        exit(0);
    }

    uint64_t target_addr = strtoull(inst.op_str, NULL, 0);
    write_absolute_jump64((void *)write_addr, (void *)target_addr);

    // auto operand_type = inst.detail->x86.operands[0].type;
    // if (operand_type == X86_OP_IMM) {
    //     int64_t target_addr = inst.detail->x86.operands[0].imm;
    // } else {
    //     std::cout << "Unsupported operand type: " << operand_type <<
    //     std::endl; exit(0);
    // }
    return 13;
}

/// @brief
/// @param inst origin instruction
/// @param write_addr the address to store the jmp instruction
/// @param target_addr the target address of the jmp instruction
/// @return
void rewrite_jmp_instruction(cs_insn &inst, uint8_t *write_addr,
                             uint8_t *target_addr) {
    uint64_t jmp_offset = target_addr - (write_addr + inst.size);

    int64_t operand_size = 0;
    if (inst.bytes[0] == 0x0f) {
        // jmp instruction starts with 0x0f, op code is 2 bytes
        operand_size = inst.size - 2;
    } else {
        operand_size = inst.size - 1;
    }

    // check jmp offset
    if (!check_mem_offset(jmp_offset, operand_size)) {
        std::cout << "Invalid jmp offset: " << jmp_offset << std::endl;
        exit(0);
    }

    if (1 == operand_size) {
        inst.bytes[operand_size] = jmp_offset;
    } else if (2 == operand_size) {
        uint16_t jmp_offset16 = jmp_offset;
        memcpy(&inst.bytes[operand_size], &jmp_offset16, operand_size);
    } else if (4 == operand_size) {
        uint32_t jmp_offset32 = jmp_offset;
        memcpy(&inst.bytes[operand_size], &jmp_offset32, operand_size);
    }
}

uint32_t add_call_to_abs_table(cs_insn &inst, uint8_t *write_addr,
                               uint8_t *jump_back_addr) {
    uint64_t target_addr = strtoull(inst.op_str, NULL, 0);
    uint32_t written_bytes =
        write_absolute_call64((void *)write_addr, (void *)target_addr);
    write_addr += written_bytes;
    // add jmp to the final jmp instruction which jump to the current call
    // instruction uint8_t jmp_bytes[2] = { 0xEB, uint8_t(jump_back_addr -
    // (write_addr + sizeof(jmp_bytes))) };
    uint8_t jmp_bytes[2] = {
        0xEB, uint8_t(jump_back_addr - (write_addr + sizeof(jmp_bytes)))};
    memcpy(write_addr, jmp_bytes, sizeof(jmp_bytes));

    return written_bytes + sizeof(jmp_bytes);
}

void rewrite_call_instruction(cs_insn &inst, uint8_t *write_addr,
                              uint8_t *target_addr) {
    int64_t jmp_offset = target_addr - (write_addr + inst.size);
    if (jmp_offset > INT8_MAX || jmp_offset < INT8_MIN) {
        std::cout << "Invalid jmp offset: " << jmp_offset << std::endl;
        exit(0);
    }
    uint8_t u8_jmp_offset = jmp_offset;
    // construct jmp instruction
    uint8_t jmp_bytes[2] = {0xEB, u8_jmp_offset};
    uint8_t nop = 0x90;
    memset(inst.bytes, nop, inst.size);
    memcpy(inst.bytes, jmp_bytes, sizeof(jmp_bytes));
}

/**
 *      |__________________________________|
 *      |______________endbr64_____________|
 *      |______________......._____________|------|
 *      |______________......._____________|      |--> stolen instructions
 *      |______________......._____________|------|
 *      |______________endbr64_____________| 4 bytes
 *      |__________mov r10, addr___________| 10 bytes = 2bytes + 8 bytes
 *      |__________jmpq r10________________| 3 bytes
 *      |__________________________________|
 **/
int64_t build_trampoline(void *func2hook, void *dstMemForTrampoline) {
    X64Instructions stolenInstrs = StealBytes(func2hook);

    uint64_t endbr64_bytes = 4;
    uint64_t mov_bytes = 10;
    uint64_t jmp_abs_bytes = 3;
    uint8_t *stolenByteMem = (uint8_t *)dstMemForTrampoline;
    // uint8_t* jumpBackMem = stolenByteMem + endbr64_bytes +
    // stolenInstrs.numBytes;
    uint8_t *jumpBackMem = stolenByteMem + stolenInstrs.numBytes;
    // 13 is the size of a 64 bit mov/jmp instruction pair
    // uint8_t* absTableMem = jumpBackMem + endbr64_bytes + mov_bytes +
    // jmp_abs_bytes;
    uint8_t *absTableMem = jumpBackMem + mov_bytes + jmp_abs_bytes;

    // first 4 bytes is for endbr64
    // stolenByteMem += endbr64_bytes;
    std::cout << "stolen memory begin: " << std::hex << stolenByteMem
              << std::endl;

    for (uint32_t i = 0; i < stolenInstrs.numInstructions; ++i) {
        cs_insn &inst = stolenInstrs.instructions[i];
        if (inst.id >= X86_INS_LOOP && inst.id <= X86_INS_LOOPNE) {
            return 0; // bail out on loop instructions, I don't have a good way
                      // of handling them
        }

        if (is_rip_relative_inst(inst)) {
            relocate_instruction(&inst, stolenByteMem);
        } else if (is_relative_jump(inst)) {
            uint64_t abs_jmp_size = add_jmp_to_abs_table(inst, absTableMem);
            rewrite_jmp_instruction(inst, stolenByteMem, absTableMem);
            absTableMem += abs_jmp_size;
        } else if (inst.id == X86_INS_CALL) {
            // uint32_t abs_call_size = add_call_to_abs_table(inst, absTableMem,
            // jumpBackMem);
            uint8_t *jump_back_addr = stolenByteMem + inst.size;
            uint32_t abs_call_size =
                add_call_to_abs_table(inst, absTableMem, jump_back_addr);
            rewrite_call_instruction(inst, stolenByteMem, absTableMem);
            absTableMem += abs_call_size;
        }
        std::cout << "memory to store stolen bytes: " << std::hex
                  << stolenByteMem << std::endl;
        memcpy(stolenByteMem, inst.bytes, inst.size);
        stolenByteMem += inst.size;
    }

    // WriteAbsoluteJump64(jumpBackMem, (uint8_t*)func2hook + 5);
    write_absolute_jump64(jumpBackMem, (uint8_t *)func2hook + 5);
    free(stolenInstrs.instructions);

    return uint32_t(absTableMem - (uint8_t *)dstMemForTrampoline);
}

void print_first_inst(void *func) {
    enable_mem_write(func);
    X64Instructions insts = StealBytes(func);
    int64_t inst_num = insts.numInstructions;
    std::cout << "First inst num: " << inst_num << std::endl;
    for (int64_t i = 0; i < inst_num; ++i) {
        cs_insn &inst = insts.instructions[i];
        std::cout << i << "st inst: " << std::endl;
        std::cout << inst.op_str << std::endl;
    }
}

void install_hook(void *hooked_func, void *payload_func,
                  void **trampoline_ptr) {
    uint8_t jmp_instrs[9] = {0xE9, 0x0, 0x0, 0x0, 0x0, 0xf3, 0x0f, 0x1e, 0xfa};

    enable_mem_write(hooked_func);
    std::cout << "payload func: " << std::hex << payload_func << std::endl;
    std::cout << "payload func new entry: " << std::hex << payload_func + 4
              << std::endl;
    int64_t addr_distance =
        ((uint64_t)payload_func + 4) - ((uint64_t)hooked_func + 9);
    if (INT32_MIN < addr_distance < INT32_MAX) {
        std::cout << "hook distance is in 32 bit range" << std::endl;
        const int32_t relative_addr_i32 = addr_distance;
        std::cout << "relative addr: " << std::hex << relative_addr_i32
                  << std::endl;
        memcpy(jmp_instrs + 1, &relative_addr_i32, sizeof(uint32_t));
        memcpy(((uint8_t *)hooked_func) + 4, jmp_instrs, sizeof(jmp_instrs));
    } else {
        void *hook_memory = alloc_page_near_address(hooked_func);
        printf("hook memory: %p\n", hook_memory);
        // std::cout << "hook memory: " << std::hex << hook_memory << std::endl;
        int64_t trampoline_size = build_trampoline(hooked_func, hook_memory);
        *trampoline_ptr = hook_memory;

        std::cout << "create relay function" << std::endl;
        // create relay function
        void *relay_func_mem = (u_int8_t *)hook_memory + trampoline_size;
        write_absolute_jump64(relay_func_mem, payload_func);

        // uint8_t jmp_instrs[9] = {0xE9, 0x0, 0x0, 0x0, 0x0, 0xf3, 0x0f, 0x1e,
        // 0xfa};
        const uint64_t relative_addr =
            (uint64_t)relay_func_mem -
            ((uint64_t)hooked_func + sizeof(jmp_instrs));
        if (relative_addr > UINT32_MAX) {
            std::cout << "Error: relative address is larger than UINT32_MAX"
                      << std::endl;
        }
        const uint32_t relative_addr_u32 = (uint32_t)relative_addr;
        memcpy(jmp_instrs + 1, &relative_addr_u32, sizeof(uint32_t));
        memcpy(((uint8_t *)hooked_func) + 4, jmp_instrs, sizeof(jmp_instrs));
    }
}

} // namespace hook