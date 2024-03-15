#include <iostream>
#include "add.h"
#include "hook.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <limits>

int(*TargetFuncTrampoline)(int64_t, int64_t) = nullptr;

int temp(int a, int b) {
    int t = a + b;
    t = TargetFuncTrampoline(a, b);
    return t;
}

// std::string get_smaps_path() {
//     pid_t pid = getpid();
//     std::string path = "/proc/" + std::to_string(pid) + "/maps";
//     return path;
// } 

// bool is_address_maped(void* addr) {
//     std::string smaps_path = get_smaps_path();
//     std::ifstream smaps_file(smaps_path.c_str());
//     std::string line;
//     uintptr_t start = 0; 
//     uintptr_t end = 0; 
//     while(std::getline(smaps_file, line)) {
//         std::cout << "line= " << line << std::endl;
//         std::istringstream iss(line);
//         iss >> std::hex >> start;
//         std::cout << "start = " << start << std::endl;
//         iss.ignore(std::numeric_limits<std::streamsize>::max(), '-');
//         iss >> std::hex >> end;
//         if (reinterpret_cast<uintptr_t>(addr) >= start && reinterpret_cast<uintptr_t>(addr) < end) {
//             // 如果地址在映射范围内，则返回true
//             std::cout << "in the map range = " << reinterpret_cast<uintptr_t>(addr) << std::endl;
//             return true;
//         }
//     }
//     return false;

// }

// uintptr_t find_free_address(uintptr_t aligned_addr, size_t size) {
//     std::string smaps_path = get_smaps_path();
//     std::ifstream smaps_file(smaps_path.c_str());
//     std::string line;
//     uintptr_t start = 0; 
//     uintptr_t end = 0; 
//     uintptr_t result = aligned_addr;
//     while(std::getline(smaps_file, line)) {
//         // std::cout << "line= " << line << std::endl;
//         std::istringstream iss(line);
//         iss >> std::hex >> start;
//         // std::cout << "start = " << start << std::endl;
//         iss.ignore(std::numeric_limits<std::streamsize>::max(), '-');
//         iss >> std::hex >> end;
//         if (end < aligned_addr) {
//             continue;
//         }
//         if (result < start && result + size < start) {
//             break;
//         } else {
//             result = end;
//         }
//     }
//     std::cout << "result = " << result << std::endl;
//     return result;
// }

// void(*TargetFuncTrampoline)(int, float) = nullptr;
int main() {
    int a = 30;
    int b = 15;
    // void* add_addr = (void*)temp;
    hook::install_hook((void*)local::add, (void*)temp, (void**)&TargetFuncTrampoline);
    std::cout << "TargetFuncTrampoline = " << std::hex << TargetFuncTrampoline << std::endl;
    // std::cout << std::hex << (uint32_t*)add_addr << std::endl;
    // std::cout << "add_addr = " << add_addr << std::endl;
    // hook::print_first_inst((void*)local::add);
    int64_t result = local::add(a, b);
    std::cout << "result = " << std::dec << result << std::endl;

    // uintptr_t add_addr = (uintptr_t)local::add;
    // // uintptr_t add_addr = 0x7f619644a000;

    // std::cout << std::hex << add_addr << std::endl;

    // static uint64_t page_size = getpagesize();
    // std::cout << "page_size = " << std::hex << page_size << std::endl;
    // uintptr_t address = ((uintptr_t)add_addr) & (~(page_size - 1));
    // uintptr_t free_mem = find_free_address((uintptr_t)address, page_size);
    // void* mmap_addr = mmap((void*)free_mem, page_size, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // if (mmap_addr == MAP_FAILED) {
    //     perror("mmap");
    //     std::cout << "mmap failed" << std::endl;
    // }
    // std::cout << "mmap success: " << mmap_addr << std::endl;
    return 0;
}