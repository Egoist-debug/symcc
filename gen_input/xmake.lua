add_rules("mode.debug", "mode.release")
add_requires("z3")

target("gen_input")
    set_kind("binary")
    set_languages("c++17")
    add_files("src/*.cpp")
    add_includedirs("include")
    add_includedirs("../runtime/include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic", "-fPIC")
    add_packages("z3")
    
    if is_mode("debug") then
        add_cxxflags("-g", "-O0")
        add_defines("DEBUG")
    end
    
    if is_mode("release") then
        add_cxxflags("-O3", "-DNDEBUG")
    end

target("gen_input_lib")
    set_kind("static")
    set_languages("c++17")
    set_basename("geninput")
    add_files("src/InputPrefix.cpp")
    add_files("src/ConstraintManager.cpp")
    add_files("src/PlaceholderEngine.cpp")
    add_files("src/ThreePhaseGenerator.cpp")
    add_files("src/SymCCIntegration.cpp")
    add_files("src/BinaryFormat.cpp")
    add_files("src/FormatAwareGenerator.cpp")
    add_includedirs("include")
    add_includedirs("../runtime/include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic", "-fPIC")
    add_packages("z3")

target("test_dns_format")
    set_kind("binary")
    set_languages("c++17")
    set_default(false)
    add_files("test/test_dns_format.cpp")
    add_files("src/BinaryFormat.cpp")
    add_files("src/FormatAwareGenerator.cpp")
    add_files("src/SymCCRunner.cpp")
    add_includedirs("include")
    add_includedirs("../runtime/include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")
    
    if is_mode("debug") then
        add_cxxflags("-g", "-O0")
    end

target("dns_parser")
    set_kind("binary")
    set_languages("c11")
    set_default(false)
    add_files("test/dns_parser.c")
    add_cflags("-Wall", "-Wextra")

target("dns_response_parser")
    set_kind("binary")
    set_languages("c11")
    set_default(false)
    add_files("test/dns_response_parser.c")
    add_cflags("-Wall", "-Wextra")
