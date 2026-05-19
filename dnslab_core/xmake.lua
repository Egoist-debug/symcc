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
        "src/follow_diff.cpp",
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

local function configure_test_target(name, source_file, deps, include_dirs)
    target(name)
        set_kind("binary")
        set_default(false)
        set_group("tests")
        set_languages("c++17")
        add_files(source_file)
        if deps then
            add_deps(table.unpack(deps))
        end
        if include_dirs then
            add_includedirs(table.unpack(include_dirs))
        end
        add_cxxflags("-Wall", "-Wextra", "-Wpedantic", "-UNDEBUG")
end

configure_test_target(
    "dnslab_core_transcript_test",
    "test/test_transcript.cpp",
    {"dnslab_core"},
    {"include", "../gen_input/include"}
)

configure_test_target(
    "dnslab_core_contract_test",
    "test/test_evidence_contract.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslab_core_lock_test",
    "test/test_resolver_lock.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslab_core_reporting_test",
    "test/test_reporting.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslab_core_oracle_test",
    "test/test_oracle.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslab_core_concrete_adapters_test",
    "test/test_concrete_adapters.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslab_core_cache_analysis_test",
    "test/test_cache_analysis.cpp",
    {"dnslab_core"},
    {"include"}
)

configure_test_target(
    "dnslabctl_batch_secondary_test",
    "test/test_batch_secondary.cpp",
    {"dnslabctl"},
    nil
)
