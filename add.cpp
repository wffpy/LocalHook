#include "add.h"

namespace local {
int64_t add(int64_t a, int64_t b) {
    int64_t temp = a + b;
    return a + temp;
}

int64_t sub(int64_t a, int64_t b) {
    auto result = a - b;
    return a - b;
}

int64_t func() {
    int64_t a = 10;
    int64_t b = 20;
    int64_t result = add(a, b);
    return result;
}

} // namespace local