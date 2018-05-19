
set(CMAKE_C_FLAGS   "-g")                     # 调试信息

add_executable(unittest_str test_stringex.c test_pnx_str.c ../stringex.c ../pnx_str.c)

add_executable(unittest_cfg test_runtime_cfg.c  ../runtime_config.h ../runtime_config.c)