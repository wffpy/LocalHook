add_executable(test test.cpp)

target_link_libraries(test PUBLIC BinaryFunc)
target_link_libraries(test PUBLIC hook)
target_link_libraries(test PUBLIC capstone)
target_link_libraries(test PUBLIC log)
target_link_libraries(test PRIVATE gtest)
target_link_libraries(test PRIVATE gtest_main)

target_link_libraries(test PUBLIC pthread)