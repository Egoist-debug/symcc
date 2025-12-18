add_rules("mode.debug", "mode.release")

package("llvm")
    on_fetch(function (package, opt)
        import("lib.detect.find_package")
        -- Use cmake to find LLVM
        return find_package("cmake::LLVM", {
            version = "14.x",
            paths = {
                "/usr/lib/llvm-14/lib/cmake/llvm",
                "/usr/lib/llvm-14/share/llvm/cmake",
                "/usr/lib/llvm-14"
            }
        })
    end)
package_end()

add_requires("llvm", {system = true})
add_requires("z3", {system = true})

option("backend")
    set_default("qsym")
    set_values("qsym", "simple")
    set_description("The symbolic backend to use.")
option_end()

option("target_32bit")
    set_default(false)
    set_description("Make the compiler work correctly with -m32")
option_end()

includes("runtime")
includes("util/symcc_fuzzing_cpp")

target("SymCC")
    set_kind("shared")
    -- Keep filename consistent with compiler/symcc.in (expects libsymcc.so).
    set_filename("libsymcc.so")
    add_files("compiler/*.cpp")
    add_packages("llvm")
    add_deps("SymCCRuntime_shared", {inherit = false})
    if has_config("target_32bit") then
        add_deps("SymCCRuntime32_shared", {inherit = false})
    end
    set_languages("c++17")
    
    add_cxxflags("-Wredundant-decls", "-Wcast-align", "-Wmissing-include-dirs", "-Wswitch-default", 
                 "-Wextra", "-Wall", "-Winvalid-pch", "-Wredundant-decls", "-Wformat=2", 
                 "-Wmissing-format-attribute", "-Wformat-nonliteral", "-Werror", "-Wno-error=deprecated-declarations")
    
    -- Mark nodelete to work around unload bug in upstream LLVM 5.0+
    add_ldflags("-Wl,-z,nodelete")

    on_load(function (target)
        local llvm = target:pkg("llvm")
        if llvm then
            -- We need to disable RTTI if LLVM is built without it, but xmake handles packages usually.
            -- However, the CMake script explicitly checks LLVM_ENABLE_RTTI.
            -- For now, we assume standard LLVM installation.
            target:add("cxflags", "-fno-rtti") 
        end
    end)

    after_build(function (target)
        import("core.project.config")
        import("lib.detect.find_tool")
        local llvm = target:pkg("llvm")
        local llvm_version_major = 0

        -- Prefer llvm-config (matches the actual toolchain) over the package's
        -- version/installdir metadata, which can be incomplete for system
        -- packages.
        local llvm_config = find_tool("llvm-config")
            or find_tool("llvm-config-14")
            or find_tool("llvm-config-13")
            or find_tool("llvm-config-12")

        local llvm_bindir = nil
        if llvm_config and llvm_config.program then
            local version = os.iorunv(llvm_config.program, {"--version"})
            if version then
                local major = tostring(version):match("^(%d+)")
                if major then
                    llvm_version_major = tonumber(major) or 0
                end
            end

            local bindir = os.iorunv(llvm_config.program, {"--bindir"})
            if bindir then
                llvm_bindir = tostring(bindir):gsub("%s+$", "")
            end
        elseif llvm then
            local version = llvm:version()
            if version then
                llvm_version_major = version:major()
            end
        end
        
        local clang_load_pass = ""
        if llvm_version_major < 13 then
            clang_load_pass = "-Xclang -load -Xclang "
        else
            clang_load_pass = "-fpass-plugin="
        end

        local clang_binary = "clang"
        local clangpp_binary = "clang++"
        -- Try to find clang in the corresponding LLVM bindir.
        if llvm_bindir and #llvm_bindir > 0 then
            local cand_clang = path.join(llvm_bindir, "clang")
            local cand_clangpp = path.join(llvm_bindir, "clang++")
            if os.isfile(cand_clang) then
                clang_binary = cand_clang
            elseif os.isfile(path.join(llvm_bindir, "clang-" .. tostring(llvm_version_major))) then
                clang_binary = path.join(llvm_bindir, "clang-" .. tostring(llvm_version_major))
            end

            if os.isfile(cand_clangpp) then
                clangpp_binary = cand_clangpp
            elseif os.isfile(path.join(llvm_bindir, "clang++-" .. tostring(llvm_version_major))) then
                clangpp_binary = path.join(llvm_bindir, "clang++-" .. tostring(llvm_version_major))
            end
        else
            -- Fallback for distros that only provide version-suffixed binaries.
            if llvm_version_major > 0 and os.isfile("/usr/bin/clang-" .. tostring(llvm_version_major)) then
                clang_binary = "/usr/bin/clang-" .. tostring(llvm_version_major)
            end
            if llvm_version_major > 0 and os.isfile("/usr/bin/clang++-" .. tostring(llvm_version_major)) then
                clangpp_binary = "/usr/bin/clang++-" .. tostring(llvm_version_major)
            end
        end

        local runtime_32bit_dir = ""
        if target:dep("SymCCRuntime32_shared") then
            runtime_32bit_dir = path.absolute(target:dep("SymCCRuntime32_shared"):targetdir())
        end

        local variables = {
            SYMCC_RUNTIME_DIR = path.absolute(target:dep("SymCCRuntime_shared"):targetdir()),
            SYMCC_RUNTIME_32BIT_DIR = runtime_32bit_dir,
            CMAKE_CURRENT_BINARY_DIR = path.absolute(target:targetdir()),
            CLANG_BINARY = clang_binary,
            CLANGPP_BINARY = clangpp_binary,
            CLANG_LOAD_PASS = clang_load_pass
        }
        
        os.cp("compiler/symcc.in", path.join(target:targetdir(), "symcc"))
        os.cp("compiler/sym++.in", path.join(target:targetdir(), "sym++"))
        
        -- Progress reporting is best-effort: some xmake versions do not provide
        -- target:offset() and/or the utils.progress module.
        local progress = import("utils.progress", {try = true})
        if progress and progress.show then
            progress.show(0, "${color.build.target}generating symcc scripts")
        else
            cprint("${color.build.target}generating symcc scripts")
        end
        
        local content = io.readfile(path.join(target:targetdir(), "symcc"))
        for k, v in pairs(variables) do
            content = content:gsub("@" .. k .. "@", v)
        end
        io.writefile(path.join(target:targetdir(), "symcc"), content)
        local symcc_path = path.join(target:targetdir(), "symcc")
        if os.chmod then
            os.chmod(symcc_path, 0755)
        else
            os.vrunv("chmod", {"755", symcc_path})
        end

        local content_pp = io.readfile(path.join(target:targetdir(), "sym++"))
        for k, v in pairs(variables) do
            content_pp = content_pp:gsub("@" .. k .. "@", v)
        end
        io.writefile(path.join(target:targetdir(), "sym++"), content_pp)
        local sympp_path = path.join(target:targetdir(), "sym++")
        if os.chmod then
            os.chmod(sympp_path, 0755)
        else
            os.vrunv("chmod", {"755", sympp_path})
        end
    end)

-- Test runner (lit + FileCheck), similar to CMake's `ninja check`.
-- Usage: `xmake run check`
target("check")
    set_kind("phony")
    set_default(false)
    add_deps("SymCC", "SymCCRuntime_shared")
    if has_config("target_32bit") then
        add_deps("SymCCRuntime32_shared")
    end

    on_run(function (_)
        import("core.project.project")
        import("lib.detect.find_tool")

        local symcc_target = project.target("SymCC")
        assert(symcc_target, "SymCC target not found")

        local projectdir = os.projectdir()
        local test_source_root = path.join(projectdir, "test")
        local test_exec_root = path.absolute(path.join(symcc_target:targetdir(), "test"))
        os.mkdir(test_exec_root)

        -- Compute FileCheck prefixes based on selected backend.
        local backend = get_config("backend") or "qsym"
        local filecheck_args = nil
        if backend == "qsym" then
            filecheck_args = "--check-prefix=QSYM --check-prefix=ANY"
        elseif backend == "simple" then
            filecheck_args = "--check-prefix=SIMPLE --check-prefix=ANY"
        else
            raise("Unknown backend to test: %s", backend)
        end

        -- Determine LLVM major version for FileCheck prefix behavior (LLVM >= 14).
        local llvm_major = 0
        do
            local llvm = symcc_target:pkg("llvm")
            if llvm and llvm:version() then
                llvm_major = llvm:version():major() or 0
            end
            if llvm_major == 0 then
                local llvmconfig = find_tool("llvm-config") or find_tool("llvm-config-14")
                if llvmconfig then
                    local out = os.iorunv(llvmconfig.program, {"--version"})
                    llvm_major = tonumber(out:match("^(%d+)")) or 0
                end
            end
        end
        if llvm_major >= 14 then
            filecheck_args = filecheck_args .. " --allow-unused-prefixes"
        end

        -- Generate lit.site.cfg from template.
        local template_path = path.join(test_source_root, "lit.site.cfg.in")
        local site_cfg_path = path.join(test_exec_root, "lit.site.cfg")
        local content = io.readfile(template_path)
        content = content:gsub("@CMAKE_CURRENT_SOURCE_DIR@", test_source_root)
        content = content:gsub("@CMAKE_CURRENT_BINARY_DIR@", test_exec_root)
        content = content:gsub("@SYM_TEST_FILECHECK_ARGS@", filecheck_args)
        content = content:gsub("@TARGET_32BIT@", has_config("target_32bit") and "ON" or "OFF")
        io.writefile(site_cfg_path, content)

        -- Help lit find LLVM tools (FileCheck) reliably.
        local lit_args = {"--verbose"}

        -- Some distros only ship version-suffixed LLVM tools (e.g., llc-14).
        -- Create small shims in the build dir so tests can call `llc`, `opt`, `FileCheck`.
        local tools_dir = path.join(test_exec_root, "tools")
        os.mkdir(tools_dir)
        local function _chmod_755(p)
            if os.chmod then
                os.chmod(p, 0755)
            else
                os.vrunv("chmod", {"755", p})
            end
        end
        local function _write_shim(name, toolnames)
            local found = nil
            for _, tname in ipairs(toolnames) do
                found = find_tool(tname)
                if found then
                    break
                end
            end
            if not found then
                return
            end
            local shim_path = path.join(tools_dir, name)
            local script = "#!/bin/sh\nexec \"" .. found.program .. "\" \"$@\"\n"
            io.writefile(shim_path, script)
            _chmod_755(shim_path)
        end
        _write_shim("llc", {"llc", "llc-14"})
        _write_shim("opt", {"opt", "opt-14"})
        _write_shim("FileCheck", {"FileCheck", "FileCheck-14"})

        -- Ensure our shims take precedence.
        table.insert(lit_args, "--path=" .. tools_dir)
        do
            local llvm_bindir = nil
            local llvm = symcc_target:pkg("llvm")
            if llvm and llvm:installdir() then
                local candidate = path.join(llvm:installdir(), "bin")
                if os.isdir(candidate) then
                    llvm_bindir = candidate
                end
            end
            if not llvm_bindir then
                local llvmconfig = find_tool("llvm-config") or find_tool("llvm-config-14")
                if llvmconfig then
                    local out = os.iorunv(llvmconfig.program, {"--bindir"}):gsub("%s+$", "")
                    if #out > 0 and os.isdir(out) then
                        llvm_bindir = out
                    end
                end
            end
            if llvm_bindir then
                table.insert(lit_args, "--path=" .. llvm_bindir)
            end
        end
        table.insert(lit_args, test_exec_root)

        cprint("${color.build.target}running lit test suite (%s backend)", backend)

        -- VS Code's xmake extension may run with a reduced environment and a
        -- PATH that does not include ~/.local/bin, even though an interactive
        -- terminal does. Be tolerant and try common locations.
        local function _find_lit_program()
            local lit = find_tool("lit")
            if lit and lit.program then
                return lit.program, {}
            end

            local home = os.getenv("HOME")
            if home then
                local cand = path.join(home, ".local", "bin", "lit")
                if os.isfile(cand) then
                    return cand, {}
                end
            end

            -- Fallback: run lit as a python module if available.
            local py = find_tool("python3") or find_tool("python")
            if py and py.program then
                -- Prefer `lit.main` which exists with LLVM's lit package.
                return py.program, {"-m", "lit.main"}
            end

            return nil, nil
        end

        local lit_program, lit_prefix_args = _find_lit_program()
        assert(lit_program, "`lit` not found. Install with: python3 -m pip install lit (and ensure ~/.local/bin is on PATH)")
        local argv = {}
        if lit_prefix_args then
            for _, a in ipairs(lit_prefix_args) do
                table.insert(argv, a)
            end
        end
        for _, a in ipairs(lit_args) do
            table.insert(argv, a)
        end
        os.vrunv(lit_program, argv)
    end)
