target("dnslab_core")
    set_kind("static")
    set_default(false)
    set_group("tools")
    set_languages("c++17")
    add_files(
        "src/process.cpp",
        "src/transcript.cpp",
        "src/evidence_contract.cpp",
        "src/cache_analysis.cpp",
        "src/concrete_adapters.cpp",
        "src/oracle.cpp",
        "src/reporting.cpp",
        "src/resolver_lock.cpp",
        "../gen_input/src/DST1Mutator.cpp",
        "../gen_input/src/FormatAwareGenerator.cpp",
        "../gen_input/src/BinaryFormat.cpp",
        "../gen_input/src/SymCCRunner.cpp"
    )
    add_includedirs("include", {public = true})
    add_includedirs("../gen_input/include", {public = false})
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")
    add_syslinks("pthread")

target("dnslabctl")
    set_kind("binary")
    set_default(false)
    set_group("tools")
    set_languages("c++17")
    add_files("src/main.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_transcript_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_transcript.cpp")
    add_deps("dnslab_core")
    add_includedirs("include", "../gen_input/include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_contract_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_evidence_contract.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_lock_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_resolver_lock.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_reporting_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_reporting.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_oracle_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_oracle.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_concrete_adapters_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_concrete_adapters.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")

target("dnslab_core_cache_analysis_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++17")
    add_files("test/test_cache_analysis.cpp")
    add_deps("dnslab_core")
    add_includedirs("include")
    add_cxxflags("-Wall", "-Wextra", "-Wpedantic")
