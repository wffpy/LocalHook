#include <iostream>
#include "../add.h"
#include "hook.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <limits>

#include <gtest/gtest.h>

int(*TargetFuncTrampoline)() = nullptr;

int temp() {
    return 100;
}

TEST(testcase, test0) {
    int a = 30;
    int b = 15;
    hook::install_hook((void*)local::func, (void*)temp, (void**)&TargetFuncTrampoline);
    std::cout << "TargetFuncTrampoline = " << std::hex << TargetFuncTrampoline << std::endl;
    int64_t result = local::func();
    std::cout << "result = " << std::dec << result << std::endl;
}

// int main() {
//     int a = 30;
//     int b = 15;
//     hook::install_hook((void*)local::func, (void*)temp, (void**)&TargetFuncTrampoline);
//     std::cout << "TargetFuncTrampoline = " << std::hex << TargetFuncTrampoline << std::endl;
//     int64_t result = local::func();
//     std::cout << "result = " << std::dec << result << std::endl;

//     return 0;
// }