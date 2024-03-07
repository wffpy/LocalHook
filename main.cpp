#include <iostream>
#include "add.h"

int main() {
    int a = 30;
    int b = 20;
    int64_t result = local::add(a, b);
    std::cout << "result = " << result << std::endl;
    return 0;
}