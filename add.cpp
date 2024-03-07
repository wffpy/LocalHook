#include "add.h"

namespace local {
int64_t add(int64_t a, int64_t b) {
    int64_t temp = 2 * a;
    return temp + b;
}

int64_t sub(int64_t a, int64_t b) {
    return a - b;
}

} // namespace local