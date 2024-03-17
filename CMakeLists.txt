project (LocalHook)

set(CMAKE_BUILD_TYPE Debug)

add_library(hook STATIC Hook/hook.cpp)
target_include_directories(hook PUBLIC ${PROJECT_SOURCE_DIR}/Hook)

add_library(BinaryFunc STATIC add.cpp)

add_library(log STATIC Log/LogStream.cpp)
target_include_directories(log PUBLIC ${PROJECT_SOURCE_DIR}/Log)

# 添加编译参数
add_compile_options(-w -std=c++11 -O2)

# 生成可执行文件
add_executable(main main.cpp)
# 链接静态/共享 库文件
target_link_libraries(main PUBLIC BinaryFunc)
target_link_libraries(main PUBLIC hook)
target_link_libraries(main PUBLIC capstone)
target_link_libraries(main PUBLIC log)
