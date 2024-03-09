#ifndef HOOK_H
#define HOOK_H
#include <iostream>

namespace hook {
void print_first_inst(void* func);
void install_hook(void* hooked_func, void* payload_func, void** trampoline_ptr);
}   // namespace hook
#endif // HOOK_H