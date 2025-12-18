这个目录是 `util/symcc_fuzzing_helper` 的 C++ 重写版（使用 xmake 构建）。

**构建**
- 在本仓库根目录下时，xmake 会优先识别上层的 `xmake.lua`；因此请显式指定项目目录：
  - `xmake f -P util/symcc_fuzzing_cpp -m release`
  - `xmake b -P util/symcc_fuzzing_cpp`
- 产物默认在：`util/symcc_fuzzing_cpp/build/linux/x86_64/release/symcc_fuzzing_helper`

**运行**
与 Rust 版保持一致：

`symcc_fuzzing_helper -a <fuzzer_name> -o <afl_output_dir> -n <symcc_name> [-v] -- <program> [args...]`

示例：
- `./build/linux/x86_64/release/symcc_fuzzing_helper -a fuzzer01 -o /path/to/afl_out -n symcc -- ./target @@`

**AFL++ bitmap 识别**
- 自动从 `fuzzer_stats` 解析 `map_size/afl_map_size/real_map_size`，并在调用 `afl-showmap` 时设置 `AFL_MAP_SIZE/AFL_MAPSIZE`。
- 在合并覆盖率时对 hitcount 做 AFL++ 风格的 bucket 归一化（避免把“同一边的更高命中次数”误当成新覆盖）。
