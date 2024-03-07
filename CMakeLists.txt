project (LocalHook)

# add_subdirectory(Printer)

# 生成动态链接库
# add_library(Printer SHARED Printer/printer.cpp)
# target_include_directories(Printer PUBLIC ${PROJECT_SOURCE_DIR}/Printer)

add_library(BinaryFunc STATIC add.cpp)
# 添加编译参数
add_compile_options(-w -std=c++11 -O2)

# 生成可执行文件
add_executable(main main.cpp)
# 链接静态/共享 库文件
target_link_libraries(main PUBLIC BinaryFunc)

# add executable for hook
# add_executable(hook_exec hook/hook.c)

# add_executable(test_exec test.cpp)