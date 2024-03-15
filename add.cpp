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

} // namespace local