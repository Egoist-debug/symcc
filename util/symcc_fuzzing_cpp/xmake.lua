target("symcc_fuzzing_helper")
  set_kind("binary")
  set_default(false)
  set_group("tools")
  set_languages("c++17")
  add_files(
    "src/**.cpp",
    "../../gen_input/src/DST1Mutator.cpp",
    "../../gen_input/src/FormatAwareGenerator.cpp",
    "../../gen_input/src/BinaryFormat.cpp",
    "../../gen_input/src/SymCCRunner.cpp"
  )
  add_includedirs("include", "../../gen_input/include", {public = false})
  add_syslinks("pthread")
