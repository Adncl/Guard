import re
import sys
from collections import defaultdict
import os
import subprocess
import shutil
import glob

def parse_make_pure_ftpd(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^(gclang|gcc|clang) .+ -c .+\.c")
    link_pattern = re.compile(r"^(gclang|gcc|clang) .+ -o (pure-ftpd|pure-pw|pure-ftpwho|pure-mrtginfo|pure-quotacheck|pure-uploadscript|pure-statsdecode|pure-pwconvert|pure-authd|pure-certd|ptracetest|example_read|example_write|regression)")
    
    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            if current_dir:
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Pure-ftpd compile command: {line}")
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Pure-ftpd link command: {line}")

    return commands

def clean_pure_ftpd_commands(commands, llvm_pass_path):
    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            link_match = re.search(r"-o\s+(pure-ftpd|pure-pw|pure-ftpwho|pure-mrtginfo|pure-quotacheck|pure-uploadscript|pure-statsdecode|pure-pwconvert|pure-authd|pure-certd|ptracetest|example_read|example_write|regression)", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            source_match = re.search(r"-c\s+([^\s]+\.c)", cmd)
            if not source_match:
                special_match = re.search(r"`test -f '([^']+\.c)' \|\| echo '\./'\`([^'\s]+\.c)", cmd)
                if special_match:
                    source_file = special_match.group(1)
                else:
                    print(f"No source file found in command: {cmd}")
                    continue
            else:
                source_file = source_match.group(1)
            
            output_match = re.search(r"-o\s+([^\s]+\.o)", cmd)
            if output_match:
                output_file = output_match.group(1)
            else:
                output_file = source_file.replace('.c', '.o')
                if '/' in output_file:
                    output_file = output_file.split('/')[-1]

            defines = re.findall(r"-D[^\s]+", cmd)
            includes = re.findall(r"-I[^\s]+", cmd)
            
            warning_flags = []
            if re.search(r"-Wall", cmd):
                warning_flags.append("-Wall")
            if re.search(r"-W(?:\s|$)", cmd):
                warning_flags.append("-W")
            warning_patterns = [
                "-Winit-self", "-Wwrite-strings", "-Wdiv-by-zero", 
                "-Wno-unused-command-line-argument"
            ]
            for pattern in warning_patterns:
                if pattern in cmd:
                    warning_flags.append(pattern)
            
            opt_flags = re.findall(r"-O[0-3s]", cmd)
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            if re.search(r"-fPIC", cmd):
                other_flags.append("-fPIC")
            if re.search(r"-fPIE", cmd):
                other_flags.append("-fPIE")
            if re.search(r"-fwrapv", cmd):
                other_flags.append("-fwrapv")
            if re.search(r"-fno-strict-aliasing", cmd):
                other_flags.append("-fno-strict-aliasing")
            if re.search(r"-fno-strict-overflow", cmd):
                other_flags.append("-fno-strict-overflow")
            if re.search(r"-fstack-protector-all", cmd):
                other_flags.append("-fstack-protector-all")
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
            if re.search(r"-MP", cmd):
                dep_flags.append("-MP")
            
            mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_match:
                dep_flags.extend(["-MF", mf_match.group(1)])
            
            mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_match:
                dep_flags.extend(["-MT", mt_match.group(1)])
            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            cleaned_cmd_parts.extend(defines)
            cleaned_cmd_parts.extend(includes)
            cleaned_cmd_parts.extend(warning_flags)
            cleaned_cmd_parts.extend(opt_flags)
            cleaned_cmd_parts.extend(debug_flags)
            cleaned_cmd_parts.extend(xclang_flags)
            cleaned_cmd_parts.extend(other_flags)
            cleaned_cmd_parts.extend(dep_flags)
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def parse_make_log_mosquitto(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^(/usr/local/go/bin/|/usr/bin/)?(g?clang\+\+|g\+\+) .+ -o .+\.o -c .+\.cpp")
    link_pattern = re.compile(r"^(/usr/local/go/bin/|/usr/bin/)?(g?clang\+\+|g\+\+) .+ -o flashmq\s+")

    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
            if current_dir:
                if compile_pattern.match(line) or link_pattern.match(line):
                    commands[current_dir].append(line)

    return commands

def parse_make_log_sol(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^(/usr/bin/|/usr/local/go/bin/)?(cc|gcc|g\+\+|clang|clang\+\+|gclang|gclang\+\+) .+ (-c .+\.(c|cpp) -o .+\.o|-o .+\.o -c .+\.(c|cpp))")
    link_pattern = re.compile("^(/usr/bin/|/usr/local/go/bin/)?(cc|gcc|g\+\+|clang|clang\+\+|gclang|gclang\+\+) .+ -o (sol|sol_test)(\s+.*|$)")

    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
            if current_dir:
                if compile_pattern.match(line) or link_pattern.match(line):
                    commands[current_dir].append(line)

    return commands

def parse_make_flashmq(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^/usr/local/go/bin/gclang\+\+ .+ -o .+\.o -c .+\.cpp")
    link_pattern = re.compile(r"^/usr/local/go/bin/gclang\+\+ .+ -o flashmq\s+")
    
    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
            if current_dir:
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                if  link_pattern.match(line):
                    commands[current_dir].append(line)

    return commands

def parse_make_tinymqtt(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^(/usr/local/go/bin/gclang|/usr/bin/clang|/usr/bin/gcc).+ -o .+\.o -c .+\.c")
    link_pattern = re.compile(r"^(/usr/local/go/bin/gclang|/usr/bin/clang|/usr/bin/gcc).+ -o (?!.*\.o\s).+")
    
    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('[') and '%' in line:
                continue
                
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            if current_dir:
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Compile command: {line}")
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Link command: {line}")

    return commands


def parse_make_dnsmasq(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^(cc|gcc|clang|gclang) .+ -c .+\.c\s*$")
    link_pattern = re.compile(r"^(cc|gcc|clang|gclang)\s+-o\s+dnsmasq\s+.+\.o.*$")
    
    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            if current_dir:
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Compile command: {line}")
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"Link command: {line}")

    return commands


def parse_make_freecoap(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    depbase_pattern = re.compile(r"^depbase=.*&&\\$")
    libtool_compile_pattern = re.compile(r"^libtool: compile:\s+gclang .+ -c .+\.c\s+.+ -o .+\.o")
    direct_compile_pattern = re.compile(r"^gclang .+ -c .+\.c\s*$")
    cd_pattern = re.compile(r"^cd\s+(.+)/$")
    skip_patterns = [
        re.compile(r"^libtool: link:"),
        re.compile(r"^/bin/bash ../libtool.*--mode=link"),
        re.compile(r"^mv -f .*\.Tpo .*\.Plo$"),
        re.compile(r"^gclang\s+.*\.o.*-o\s+\w+\s+"),
    ]
    
    commands = defaultdict(list)
    current_dir = None
    cd_target_dir = None
    in_multiline_command = False

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                    cd_target_dir = None
                continue
            
            cd_match = cd_pattern.match(line)
            if cd_match:
                cd_target_dir = cd_match.group(1)
                if current_dir:
                    if cd_target_dir.startswith('/'):
                        cd_target_dir = cd_target_dir
                    else:
                        cd_target_dir = os.path.join(current_dir, cd_target_dir)
                print(f"CD command detected, target directory: {cd_target_dir}")
                continue
            
            should_skip = False
            for skip_pattern in skip_patterns:
                if skip_pattern.match(line):
                    should_skip = True
                    break
            if should_skip:
                continue
            
            if depbase_pattern.match(line):
                in_multiline_command = True
                continue
            
            if in_multiline_command:
                if line.startswith("/bin/bash ../libtool") and "--mode=compile" in line:
                    in_multiline_command = False
                continue
            
            effective_dir = cd_target_dir or current_dir
            if effective_dir:
                if libtool_compile_pattern.match(line):
                    commands[effective_dir].append(line)
                    print(f"Libtool compile command: {line}")
                elif direct_compile_pattern.match(line):
                    commands[effective_dir].append(line)
                    print(f"Direct compile command in {effective_dir}: {line}")

    return commands

def parse_make_libcoap(log_file):
    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    compile_pattern = re.compile(r"^/usr/local/go/bin/gclang\s+.*-c\s+.*\.c$")
    
    skip_patterns = [
        re.compile(r"^/usr/local/cmake/bin/cmake"),
        re.compile(r"^/usr/bin/ar\s+"),
        re.compile(r"^/usr/bin/ranlib\s+"),
        re.compile(r"^\[\s*\d+%\]\s+"),
        re.compile(r"^make\s+"),
        re.compile(r"^cd\s+"),
        re.compile(r"^/usr/local/go/bin/gclang.*-o\s+(?!.*\.o\s).*$"),
    ]
    
    commands = defaultdict(list)
    current_dir = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue

            should_skip = False
            for skip_pattern in skip_patterns:
                if skip_pattern.match(line):
                    should_skip = True
                    break
            if should_skip:
                continue

            if current_dir and compile_pattern.match(line):
                commands[current_dir].append(line)
                print(f"Libcoap compile command: {line}")

    return commands

def clean_mosquitto_commands(commands, llvm_pass_paths):
    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            
            compiler_match = re.match(r"^(clang|gcc|g\+\+|clang\+\+|gclang|gclang\+\+)", cmd)
            if not compiler_match:
                continue
            compiler = compiler_match.group(1)
            
            
            defines = re.findall(r"-D\s*[^\s]+", cmd)

            
            include_paths = re.findall(r"-I\s*[^\s]+", cmd)

            
            source_file = re.search(r"-c\s+([^\s]+\.(c|cpp))", cmd)
            output_file = re.search(r"-o\s+([^\s]+\.o)", cmd)

            if not source_file or not output_file:
                continue

            
            cleaned_cmd = f"{compiler} -Xclang -load -Xclang {llvm_pass_paths} -Xclang -plugin -Xclang cf-analyzer {' '.join(defines)} {' '.join(include_paths)} -c {source_file.group(1)} -o {output_file.group(1)}"
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_sol_commands(commands, llvm_pass_paths):

    cleaned_commands = defaultdict(list)
    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")
                
            
            compiler_match = re.match(r"^(/usr/local/go/bin/gclang|/usr/bin/clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)
            
            
            
            defines = re.findall(r"-D[^\s]+", cmd)

            
            flags = []
            flags_match = re.search(r"-Wall -Wunused -Werror -pedantic\s+[^-]*", cmd)
            if flags_match:
                flags = flags_match.group(0).strip().split()
            
            
            std_flag = re.search(r"-std=[^\s]+", cmd)
            if std_flag:
                flags.append(std_flag.group(0))
                
            disable_flags = re.findall(r"-Xclang -disable-[^\s]+", cmd)
            for flag in disable_flags:
                flags.append(flag)
                
            
            source_file = re.search(r"-c\s+([^\s]+\.(c|cpp))", cmd)
            output_file = re.search(r"-o\s+([^\s]+\.o)", cmd)

            if not source_file or not output_file:
                print(f"Source or output file not found in command: {cmd}")
                continue

            
            cleaned_cmd = f"{compiler} -Xclang -load -Xclang {llvm_pass_paths} -Xclang -plugin -Xclang cf-analyzer {' '.join(defines)} {' '.join(flags)} -c {source_file.group(1)} -o {output_file.group(1)}"
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_flashmq_commands(commands, llvm_pass_paths):

    cleaned_commands = defaultdict(list)
    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")
                
            
            compiler_match = re.match(r"^(/usr/local/go/bin/|/usr/bin/)?(g?clang\+\+|g\+\+|gcc)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler_path = compiler_match.group(1) or ""
            compiler_name = compiler_match.group(2)
            compiler = compiler_path + compiler_name
            
            
            output_match = re.search(r"-o\s+([^\s]+)", cmd)
            if output_match:
                output_file = output_match.group(1)
                
                if not output_file.endswith('.o') or "cmake_link_script" in cmd:
                    print(f"Skipping linking command: {cmd}")
                    continue
            
            
            defines = re.findall(r"-D[^\s]+", cmd)

            
            flags = []
            
            
            arch_flags = re.findall(r"-msse4\.2", cmd)
            flags.extend(arch_flags)
            
            
            if re.search(r"-g(?:\s|$)", cmd):
                flags.append("-g")
            
            
            opt_flags = re.findall(r"-O[0-3s]", cmd)
            flags.extend(opt_flags)
            
            
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            if re.search(r"-fno-discard-value-names", cmd):
                flags.append("-fno-discard-value-names")
            
            std_flag = re.search(r"-std=[^\s]+", cmd)
            if std_flag:
                flags.append(std_flag.group(0))
                
            if re.search(r"-Wall", cmd):
                flags.append("-Wall")
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
                
            mt_flag = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_flag:
                dep_flags.extend(["-MT", mt_flag.group(1)])
                
            mf_flag = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_flag:
                dep_flags.extend(["-MF", mf_flag.group(1)])
            
            
            source_file = re.search(r"-c\s+([^\s]+\.cpp)", cmd)
            output_file = re.search(r"-o\s+([^\s]+\.o)", cmd)

            if not source_file or not output_file:
                print(f"Source or output file not found in command: {cmd}")
                continue

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_paths,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(flags)
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file.group(1), "-o", output_file.group(1)])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_tinymqtt_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(/usr/local/go/bin/gclang|/usr/bin/clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            args = cmd.strip().split()

            
            defines = []
            includes = []
            flags = []
            disable_flags = []

            source_file = None
            output_file = None

            idx = 0
            while idx < len(args):
                arg = args[idx]
                if arg == "-D":
                    defines.append(f"-D{args[idx+1]}")
                    idx += 2
                elif arg.startswith("-D"):
                    defines.append(arg)
                    idx += 1
                elif arg.startswith("-I"):
                    includes.append(arg)
                    idx += 1
                elif arg == "-Xclang" and idx + 1 < len(args):
                    if args[idx+1].startswith("-disable-"):
                        disable_flags.append(f"-Xclang {args[idx+1]}")
                    idx += 2
                elif arg == "-std" and idx + 1 < len(args):
                    flags.append(f"-std {args[idx+1]}")
                    idx += 2
                elif arg.startswith("-std="):
                    flags.append(arg)
                    idx += 1
                elif arg == "-o" and idx + 1 < len(args):
                    output_file = args[idx+1]
                    idx += 2
                elif arg == "-c" and idx + 1 < len(args):
                    source_file = args[idx+1]
                    idx += 2
                else:
                    
                    flags.append(arg)
                    idx += 1

            
            if not source_file or not output_file:
                print(f"Missing source or output file in command: {cmd}")
                continue

            
            cleaned_cmd = (
                f"{compiler} "
                f"-Xclang -load -Xclang {llvm_pass_path} "
                f"-Xclang -plugin -Xclang cf-analyzer "
                f"{' '.join(defines)} "
                f"{' '.join(includes)} "
                f"{' '.join(flags)} "
                f"{' '.join(disable_flags)} "
                f"-c {source_file} -o {output_file}"
            )

            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_dnsmasq_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(cc|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+(\w+)\s+.*\.o", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            source_match = re.search(r"-c\s+([^\s]+\.c)", cmd)
            if not source_match:
                print(f"No source file found in command: {cmd}")
                continue
            
            source_file = source_match.group(1)
            
            output_file = source_file.replace('.c', '.o')

            
            defines = re.findall(r"-D[^\s]+", cmd)
            
            
            warning_flags = []
            if re.search(r"-Wall", cmd):
                warning_flags.append("-Wall")
            if re.search(r"-W(?:\s|$)", cmd):
                warning_flags.append("-W")
            
            
            opt_flags = re.findall(r"-O[0-3s]", cmd)
            
            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(opt_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_freecoap_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            if cmd.startswith("libtool: compile:"):
                
                actual_cmd = cmd.replace("libtool: compile:", "").strip()
                
                
                compiler_match = re.match(r"^(gclang|gcc|clang)", actual_cmd)
                if not compiler_match:
                    print(f"Unsupported compiler in libtool command: {actual_cmd}")
                    continue
                compiler = compiler_match.group(1)
                
                
                source_match = re.search(r"-c\s+([^\s]+\.c)", actual_cmd)
                if not source_match:
                    print(f"No source file found in libtool command: {actual_cmd}")
                    continue
                source_file = source_match.group(1)
                
                
                output_match = re.search(r"-o\s+([^\s]+\.o)", actual_cmd)
                if output_match:
                    output_file = output_match.group(1)
                else:
                    
                    output_file = source_file.replace('.c', '.o')
                
                
                defines = re.findall(r"-D[^\s]+", actual_cmd)
                includes = re.findall(r"-I[^\s]+", actual_cmd)
                
                
                debug_flags = []
                if re.search(r"-g(?:\s|$)", actual_cmd):
                    debug_flags.append("-g")
                
                
                xclang_flags = []
                if re.search(r"-Xclang\s+-disable-O0-optnone", actual_cmd):
                    xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
                
                
                other_flags = []
                if re.search(r"-fno-discard-value-names", actual_cmd):
                    other_flags.append("-fno-discard-value-names")
                if re.search(r"-fPIC", actual_cmd):
                    other_flags.append("-fPIC")
                if re.search(r"-DPIC", actual_cmd):
                    other_flags.append("-DPIC")
                
            
            else:
                
                compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
                if not compiler_match:
                    print(f"Unsupported compiler in direct command: {cmd}")
                    continue
                compiler = compiler_match.group(1)
                
                
                source_match = re.search(r"-c\s+([^\s]+\.c)", cmd)
                if not source_match:
                    print(f"No source file found in direct command: {cmd}")
                    continue
                source_file = source_match.group(1)
                
                
                output_file = source_file.replace('.c', '.o')
                
                if '/' in output_file:
                    output_file = output_file.split('/')[-1]
                
                
                defines = re.findall(r"-D[^\s]+", cmd)
                includes = re.findall(r"-I[^\s]+", cmd)
                
                
                debug_flags = []
                if re.search(r"-g(?:\s|$)", cmd):
                    debug_flags.append("-g")
                
                
                xclang_flags = []
                if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                    xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
                
                
                other_flags = []
                if re.search(r"-fno-discard-value-names", cmd):
                    other_flags.append("-fno-discard-value-names")

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def clean_libcoap_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(/usr/local/go/bin/gclang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)
            
            
            source_match = re.search(r"-c\s+([^\s]+\.c)$", cmd)
            if not source_match:
                print(f"No source file found in command: {cmd}")
                continue
            source_file = source_match.group(1)
            
            
            output_match = re.search(r"-o\s+([^\s]+\.o)", cmd)
            if not output_match:
                print(f"No output file found in command: {cmd}")
                continue
            output_file = output_match.group(1)
            
            
            includes = re.findall(r"-I[^\s]+", cmd)
            
            
            defines = re.findall(r'-D[^\s]+(?:"[^"]*")?', cmd)
            
            
            debug_flags = []
            
            debug_count = cmd.count(' -g ')
            for _ in range(debug_count):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            std_match = re.search(r"-std=[^\s]+", cmd)
            if std_match:
                other_flags.append(std_match.group(0))
            
            
            warning_flags = []
            warning_patterns = [
                "-pedantic", "-Wall", "-Wcast-qual", "-Wextra", 
                "-Wformat-security", "-Winline", "-Wmissing-declarations",
                "-Wmissing-prototypes", "-Wnested-externs", "-Wpointer-arith",
                "-Wshadow", "-Wstrict-prototypes", "-Wswitch-default",
                "-Wswitch-enum", "-Wunused", "-Wwrite-strings"
            ]
            for pattern in warning_patterns:
                if pattern in cmd:
                    warning_flags.append(pattern)
            
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
            
            mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_match:
                dep_flags.extend(["-MT", mt_match.group(1)])
            
            mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_match:
                dep_flags.extend(["-MF", mf_match.group(1)])

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def parse_make_log_uftpd(log_file):

    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    
    compile_pattern = re.compile(r"^(gclang|gcc|clang) .+ -c .+\.c")
    
    link_pattern = re.compile(r"^(gclang|gcc|clang) .+ -o uftpd\s+")
    
    
    commands = defaultdict(list)
    current_dir = None

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith("mv -f"):
                continue
                
            
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            
            if current_dir:
                
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"uftpd compile command: {line}")
                
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"uftpd link command: {line}")

    return commands

def clean_uftpd_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+uftpd\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            
            
            source_match = re.search(r"-c\s+([^\s]+\.c)", cmd)
            if not source_match:
                
                special_match = re.search(r"`test -f '([^']+\.c)' \|\| echo '\./'\`([^'\s]+\.c)", cmd)
                if special_match:
                    
                    source_file = special_match.group(1)
                else:
                    print(f"No source file found in command: {cmd}")
                    continue
            else:
                source_file = source_match.group(1)
            
            
            output_match = re.search(r"-o\s+([^\s]+\.o)", cmd)
            if output_match:
                output_file = output_match.group(1)
            else:
                
                output_file = source_file.replace('.c', '.o')
                
                if '/' in output_file:
                    output_file = output_file.split('/')[-1]

            
            defines = re.findall(r"-D[^\s]+", cmd)
            includes = re.findall(r"-I[^\s]+", cmd)
            
            
            warning_flags = []
            if re.search(r"-Wall", cmd):
                warning_flags.append("-Wall")
            if re.search(r"-W(?:\s|$)", cmd):
                warning_flags.append("-W")
            if re.search(r"-Wextra", cmd):
                warning_flags.append("-Wextra")
            if re.search(r"-Wno-unused-parameter", cmd):
                warning_flags.append("-Wno-unused-parameter")
            
            
            std_match = re.search(r"-std=[^\s]+", cmd)
            std_flags = [std_match.group(0)] if std_match else []
            
            
            opt_flags = re.findall(r"-O[0-3s]", cmd)
            
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
            if re.search(r"-MP", cmd):
                dep_flags.append("-MP")
            
            mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_match:
                dep_flags.extend(["-MF", mf_match.group(1)])
            
            mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_match:
                dep_flags.extend(["-MT", mt_match.group(1)])
            
            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(std_flags)
            
            
            cleaned_cmd_parts.extend(opt_flags)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands


def parse_make_log_uFTP(log_file):

    
    
    compile_pattern = re.compile(r"^gclang\s+-c\s+.*\.c\s+-o\s+.*\.o$")
    
    link_pattern = re.compile(r"^gclang\s+.*-o\s+\./build/uFTP\s+")
    
    
    commands = defaultdict(list)
    current_dir = "."  

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith("echo ") or line.startswith("Compiler:") or line.startswith("Output Directory:") or line.startswith("CGI FILES:") or line.startswith("Clean ok") or line.startswith("rm -rf") or line.startswith("Build process end"):
                continue
            
            
            if line.endswith("\\") or (line.startswith("./build/modules/") and line.endswith(".o")):
                continue
                
            
            if compile_pattern.match(line):
                commands[current_dir].append(line)
                print(f"uFTP compile command: {line}")
            
            elif link_pattern.match(line):
                commands[current_dir].append(line)
                print(f"uFTP link command: {line}")

    return commands

def clean_uFTP_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+\./build/uFTP\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            source_match = re.search(r"-c\s+.*?([^\s]+\.c)\s+-o", cmd)
            if not source_match:
                print(f"No source file found in command: {cmd}")
                continue
            source_file = source_match.group(1)
            
            
            output_match = re.search(r"-o\s+([^\s]+\.o)", cmd)
            if not output_match:
                print(f"No output file found in command: {cmd}")
                continue
            output_file = output_match.group(1)

            
            defines = re.findall(r"-D\s*[^\s]+", cmd)
            includes = re.findall(r"-I\s*[^\s]+", cmd)
            
            
            warning_flags = []
            if re.search(r"-Wall", cmd):
                warning_flags.append("-Wall")
            
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def parse_make_log_dhcp(log_file):

    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    
    
    compile_pattern1 = re.compile(r"^gclang .+ -c -o .+\.o `test -f '.+\.c' \|\| echo '\./'\`.+\.c")
    
    compile_pattern2 = re.compile(r"^gclang .+ -c -o .+\.o .+\.c$")
    
    link_pattern = re.compile(r"^gclang .+ -o dhcpd\s+")
    
    
    commands = defaultdict(list)
    current_dir = None

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith("mv -f") or line.startswith("Making all") or line.startswith("rm -f") or line.startswith("/usr/bin/ar") or line.startswith("ranlib"):
                continue
                
            
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            
            if current_dir:
                
                if compile_pattern1.match(line) or compile_pattern2.match(line):
                    commands[current_dir].append(line)
                    print(f"DHCP compile command: {line}")
                
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"DHCP link command: {line}")

    return commands

def clean_dhcp_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+dhcpd\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            
            
            source_file = None
            
            
            special_match = re.search(r"`test -f '([^']+\.c)' \|\| echo '\./'\`([^'\s]+\.c)", cmd)
            if special_match:
                
                source_file = special_match.group(1)
            else:
                
                standard_match = re.search(r"-c -o\s+[^\s]+\.o\s+([^\s]+\.c)$", cmd)
                if standard_match:
                    source_file = standard_match.group(1)
            
            if not source_file:
                print(f"No source file found in command: {cmd}")
                continue
            
            
            output_match = re.search(r"-c -o\s+([^\s]+\.o)", cmd)
            if not output_match:
                print(f"No output file found in command: {cmd}")
                continue
            output_file = output_match.group(1)

            
            defines = re.findall(r"-D[^\s]+", cmd)
            includes = re.findall(r"-I[^\s]+", cmd)
            
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
            if re.search(r"-MP", cmd):
                dep_flags.append("-MP")
            
            mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_match:
                dep_flags.extend(["-MF", mf_match.group(1)])
            
            mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_match:
                dep_flags.extend(["-MT", mt_match.group(1)])

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(["-c", source_file, "-o", output_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def parse_make_log_ndhs(log_file):

    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    
    
    compile_pattern = re.compile(r"^gclang .+ -c -o .+\.o .+\.c$")
    
    link_pattern = re.compile(r"^gclang .+ -o ndhs\s+")
    
    
    commands = defaultdict(list)
    current_dir = "."  

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line:
                continue
                
            
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = "."
                continue
            
            
            
            if compile_pattern.match(line):
                commands[current_dir].append(line)
                print(f"NDHS compile command: {line}")
            
            elif link_pattern.match(line):
                commands[current_dir].append(line)
                print(f"NDHS link command: {line}")

    return commands

def clean_ndhs_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(gclang|gcc|clang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+ndhs\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            source_match = re.search(r"-c -o\s+[^\s]+\.o\s+([^\s]+\.c)$", cmd)
            if not source_match:
                print(f"No source file found in command: {cmd}")
                continue
            source_file = source_match.group(1)
            
            
            output_match = re.search(r"-c -o\s+([^\s]+\.o)", cmd)
            if not output_match:
                print(f"No output file found in command: {cmd}")
                continue
            output_file = output_match.group(1)

            
            defines = re.findall(r"-D[^\s]+", cmd)
            includes = re.findall(r"-I[^\s]+", cmd)
            
            
            std_match = re.search(r"-std=[^\s]+", cmd)
            std_flags = [std_match.group(0)] if std_match else []
            
            
            warning_flags = []
            warning_patterns = [
                "-Wall", "-Wextra", "-Wimplicit-fallthrough=0", "-Wformat=2",
                "-Wformat-nonliteral", "-Wformat-security", "-Wshadow", 
                "-Wpointer-arith", "-Wmissing-prototypes", "-Wcast-qual",
                "-Wsign-conversion", "-Wno-discarded-qualifiers"
            ]
            for pattern in warning_patterns:
                if pattern in cmd:
                    warning_flags.append(pattern)
            
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            dep_flags = []
            if re.search(r"-MMD", cmd):
                dep_flags.append("-MMD")

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(std_flags)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(["-c", "-o", output_file, source_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands

def parse_make_log_tlse(log_file):

    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    
    
    compile_pattern1 = re.compile(r"^/usr/local/go/bin/gclang .+ -o .+\.c\.o -c .+\.c$")
    
    compile_pattern2 = re.compile(r"^cd .+ && /usr/local/go/bin/gclang .+ -o .+\.c\.o -c .+\.c$")
    
    link_pattern = re.compile(r"^/usr/local/go/bin/gclang .+ -o (tlsclienthello|tlshelloworld|tlssimple|tlssimpleserver)\s+")
    
    
    commands = defaultdict(list)
    current_dir = None

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith("[") or line.startswith("/usr/local/cmake") or line.startswith("/usr/bin/make") or line.startswith("/usr/bin/llvm-") or line.startswith("Built target") or line.startswith("Linking C"):
                continue
                
            
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            
            if current_dir:
                
                if compile_pattern1.match(line):
                    commands[current_dir].append(line)
                    print(f"TLSe direct compile command: {line}")
                
                elif compile_pattern2.match(line):
                    commands[current_dir].append(line)
                    print(f"TLSe cd compile command: {line}")
                
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"TLSe link command: {line}")

    return commands

def clean_tlse_commands(commands, llvm_pass_path):
    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            link_match = re.search(r"-o\s+(tlsclienthello|tlshelloworld|tlssimple|tlssimpleserver)\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            if cmd.startswith("cd ") and " && " in cmd:
                
                parts = cmd.split(" && ", 1)
                if len(parts) != 2:
                    print(f"Invalid cd && command format: {cmd}")
                    continue
                
                cd_part = parts[0]  
                compile_part = parts[1]  
                
                
                cd_match = re.match(r"cd\s+(.+)", cd_part)
                if not cd_match:
                    print(f"Cannot extract cd directory from: {cd_part}")
                    continue
                work_dir = cd_match.group(1)
                
                
                compiler_match = re.match(r"^(/usr/local/go/bin/gclang)", compile_part)
                if not compiler_match:
                    print(f"Unsupported compiler in command: {compile_part}")
                    continue
                compiler = compiler_match.group(1)
                
                
                source_match = re.search(r"-c\s+([^\s]+\.c)$", compile_part)
                if not source_match:
                    print(f"No source file found in command: {compile_part}")
                    continue
                source_file = source_match.group(1)
                
                
                output_match = re.search(r"-o\s+([^\s]+\.c\.o)", compile_part)
                if not output_match:
                    print(f"No output file found in command: {compile_part}")
                    continue
                output_file = output_match.group(1)

                
                defines = re.findall(r"-D[^\s]+", compile_part)
                includes = re.findall(r"-I[^\s]+", compile_part)
                
                
                debug_flags = []
                if re.search(r"-g(?:\s|$)", compile_part):
                    debug_flags.append("-g")
                
                
                xclang_flags = []
                if re.search(r"-Xclang\s+-disable-O0-optnone", compile_part):
                    xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
                
                
                other_flags = []
                if re.search(r"-fno-discard-value-names", compile_part):
                    other_flags.append("-fno-discard-value-names")
                
                
                dep_flags = []
                if re.search(r"-MD", compile_part):
                    dep_flags.append("-MD")
                
                mt_match = re.search(r"-MT\s+([^\s]+)", compile_part)
                if mt_match:
                    dep_flags.extend(["-MT", mt_match.group(1)])
                
                mf_match = re.search(r"-MF\s+([^\s]+)", compile_part)
                if mf_match:
                    dep_flags.extend(["-MF", mf_match.group(1)])

                
                cleaned_cmd_parts = [
                    "cd", work_dir, "&&",
                    compiler,
                    "-Xclang", "-load", "-Xclang", llvm_pass_path,
                    "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
                ]
                
                
                cleaned_cmd_parts.extend(defines)
                
                
                cleaned_cmd_parts.extend(includes)
                
                
                cleaned_cmd_parts.extend(debug_flags)
                
                
                cleaned_cmd_parts.extend(xclang_flags)
                
                
                cleaned_cmd_parts.extend(other_flags)
                
                
                cleaned_cmd_parts.extend(dep_flags)
                
                
                cleaned_cmd_parts.extend(["-o", output_file, "-c", source_file])
                
                cleaned_cmd = " ".join(cleaned_cmd_parts)
                cleaned_commands[directory].append(cleaned_cmd)
            
            elif cmd.startswith("/usr/local/go/bin/gclang"):
                
                
                compiler_match = re.match(r"^(/usr/local/go/bin/gclang)", cmd)
                if not compiler_match:
                    print(f"Unsupported compiler in command: {cmd}")
                    continue
                compiler = compiler_match.group(1)
                
                
                source_match = re.search(r"-c\s+([^\s]+\.c)$", cmd)
                if not source_match:
                    print(f"No source file found in command: {cmd}")
                    continue
                source_file = source_match.group(1)
                
                
                output_match = re.search(r"-o\s+([^\s]+\.c\.o)", cmd)
                if not output_match:
                    print(f"No output file found in command: {cmd}")
                    continue
                output_file = output_match.group(1)

                
                defines = re.findall(r"-D[^\s]+", cmd)
                includes = re.findall(r"-I[^\s]+", cmd)
                
                
                debug_flags = []
                if re.search(r"-g(?:\s|$)", cmd):
                    debug_flags.append("-g")
                
                
                xclang_flags = []
                if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                    xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
                
                
                other_flags = []
                if re.search(r"-fno-discard-value-names", cmd):
                    other_flags.append("-fno-discard-value-names")
                
                
                dep_flags = []
                if re.search(r"-MD", cmd):
                    dep_flags.append("-MD")
                
                mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
                if mt_match:
                    dep_flags.extend(["-MT", mt_match.group(1)])
                
                mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
                if mf_match:
                    dep_flags.extend(["-MF", mf_match.group(1)])

                
                cleaned_cmd_parts = [
                    compiler,
                    "-Xclang", "-load", "-Xclang", llvm_pass_path,
                    "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
                ]
                
                
                cleaned_cmd_parts.extend(defines)
                
                
                cleaned_cmd_parts.extend(includes)
                
                
                cleaned_cmd_parts.extend(debug_flags)
                
                
                cleaned_cmd_parts.extend(xclang_flags)
                
                
                cleaned_cmd_parts.extend(other_flags)
                
                
                cleaned_cmd_parts.extend(dep_flags)
                
                
                cleaned_cmd_parts.extend(["-o", output_file, "-c", source_file])
                
                cleaned_cmd = " ".join(cleaned_cmd_parts)
                cleaned_commands[directory].append(cleaned_cmd)
            
            else:
                
                print(f"Unsupported command format: {cmd}")
                continue

    return cleaned_commands


def parse_make_log_wolfssl(log_file):

    dir_pattern = re.compile(r"make\[\d+\]: (Entering|Leaving) directory '([^']+)'")
    
    
    compile_pattern = re.compile(r"^/usr/local/go/bin/gclang .+ -o .+\.o -c .+\.c$")
    
    link_pattern = re.compile(r"^/usr/local/go/bin/gclang .+ -o (client|server|echoclient|echoserver|tls_bench|testwolfcrypt|benchmark)\s+")
    
    
    commands = defaultdict(list)
    current_dir = None

    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith("[") or line.startswith("/usr/local/cmake") or line.startswith("/usr/bin/make") or line.startswith("/usr/bin/llvm-") or line.startswith("Built target") or line.startswith("Linking C") or line.startswith("/usr/bin/ar") or line.startswith("/usr/bin/ranlib"):
                continue
                
            
            dir_match = dir_pattern.match(line)
            if dir_match:
                action, directory = dir_match.groups()
                if action == "Entering":
                    current_dir = directory
                elif action == "Leaving":
                    current_dir = None
                continue
            
            
            if current_dir:
                
                if compile_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"wolfSSL compile command: {line}")
                
                elif link_pattern.match(line):
                    commands[current_dir].append(line)
                    print(f"wolfSSL link command: {line}")

    return commands

def clean_wolfssl_commands(commands, llvm_pass_path):

    cleaned_commands = defaultdict(list)

    for directory, cmds in commands.items():
        for cmd in cmds:
            print(f"Processing command: {cmd}")

            
            compiler_match = re.match(r"^(/usr/local/go/bin/gclang)", cmd)
            if not compiler_match:
                print(f"Unsupported compiler in command: {cmd}")
                continue
            compiler = compiler_match.group(1)

            
            link_match = re.search(r"-o\s+(client|server|echoclient|echoserver|tls_bench|testwolfcrypt|benchmark|unit\.test)\s+", cmd)
            if link_match:
                print(f"Skipping linking command: {cmd}")
                continue

            
            source_match = re.search(r"-c\s+([^\s]+\.c)$", cmd)
            if not source_match:
                print(f"No source file found in command: {cmd}")
                continue
            source_file = source_match.group(1)
            
            
            output_match = re.search(r"-o\s+([^\s]+\.o)", cmd)
            if not output_match:
                print(f"No output file found in command: {cmd}")
                continue
            output_file = output_match.group(1)

            
            defines = re.findall(r"-D[^\s]+", cmd)
            includes = re.findall(r"-I[^\s]+", cmd)
            
            
            warning_flags = []
            if re.search(r"-Wall", cmd):
                warning_flags.append("-Wall")
            if re.search(r"-Wextra", cmd):
                warning_flags.append("-Wextra")
            if re.search(r"-Wno-unused", cmd):
                warning_flags.append("-Wno-unused")
            if re.search(r"-Werror", cmd):
                warning_flags.append("-Werror")
            
            
            debug_flags = []
            if re.search(r"-g(?:\s|$)", cmd):
                debug_flags.append("-g")
            
            
            xclang_flags = []
            if re.search(r"-Xclang\s+-disable-O0-optnone", cmd):
                xclang_flags.extend(["-Xclang", "-disable-O0-optnone"])
            
            
            other_flags = []
            if re.search(r"-fno-discard-value-names", cmd):
                other_flags.append("-fno-discard-value-names")
            
            
            dep_flags = []
            if re.search(r"-MD", cmd):
                dep_flags.append("-MD")
            
            mt_match = re.search(r"-MT\s+([^\s]+)", cmd)
            if mt_match:
                dep_flags.extend(["-MT", mt_match.group(1)])
            
            mf_match = re.search(r"-MF\s+([^\s]+)", cmd)
            if mf_match:
                dep_flags.extend(["-MF", mf_match.group(1)])

            
            cleaned_cmd_parts = [
                compiler,
                "-Xclang", "-load", "-Xclang", llvm_pass_path,
                "-Xclang", "-plugin", "-Xclang", "cf-analyzer"
            ]
            
            
            cleaned_cmd_parts.extend(defines)
            
            
            cleaned_cmd_parts.extend(includes)
            
            
            cleaned_cmd_parts.extend(warning_flags)
            
            
            cleaned_cmd_parts.extend(debug_flags)
            
            
            cleaned_cmd_parts.extend(xclang_flags)
            
            
            cleaned_cmd_parts.extend(other_flags)
            
            
            cleaned_cmd_parts.extend(dep_flags)
            
            
            cleaned_cmd_parts.extend(["-o", output_file, "-c", source_file])
            
            cleaned_cmd = " ".join(cleaned_cmd_parts)
            cleaned_commands[directory].append(cleaned_cmd)

    return cleaned_commands


def save_command_script(commands, output_file, project_name):

    script_path = os.path.splitext(output_file)[0] + ".sh"  

    with open(script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n\n")  

        supported_projects = ["mosquitto", "sol", "flashmq", "tinymqtt", "dnsmasq", "freecoap", "libcoap", "pure-ftpd", "uftpd", "uftp", "dhcp", "ndhs", "tlse", "wolfssl"]
        if project_name.lower() in supported_projects:
            for directory, cmds in commands.items():
                f.write(f"# Directory: {directory}\n")
                f.write(f"cd {directory} 1>/dev/null || {{ echo 'Directory {directory} not found'; exit 1; }}\n")  
                for cmd in cmds:
                    f.write(f"{cmd} 1>/dev/null\n")  
                f.write("\n")
            f.write("echo 'All commands executed successfully'\n")
        else:
            f.write(f"# Project {project_name} is not supported yet\n")
            f.write("echo 'Unsupported project'\n")

    
    os.chmod(script_path, 0o755)
    print(f"Bash script saved to {script_path}")




def save_commands(commands, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        for directory, cmds in commands.items():
            f.write(f"# Directory: {directory}\n")
            for cmd in cmds:
                f.write(f"{cmd}\n")
            f.write("\n")

def print_usage():
    print("Usage: python extract_commands.py <input_log_file> <output_file> <project_name> <llvm_pass_path>")
    print("Example: python extract_commands.py make.log extracted_commands.txt mosquitto /path/libASTPass.so")

if __name__ == "__main__":
    
    if len(sys.argv) != 5:
        print_usage()
        sys.exit(1)

    
    log_file = sys.argv[1]
    output_file = sys.argv[2]
    project_name = sys.argv[3].lower()  
    llvm_pass_paths = sys.argv[4]

    
    if project_name == "mosquitto":
        commands = parse_make_log_mosquitto(log_file)
        commands = clean_mosquitto_commands(commands, llvm_pass_paths)
    elif project_name == "sol":
        commands = parse_make_log_sol(log_file)
        commands = clean_sol_commands(commands, llvm_pass_paths)
    elif project_name == "flashmq":
        commands = parse_make_flashmq(log_file)
        commands = clean_flashmq_commands(commands, llvm_pass_paths)
    elif project_name == "tinymqtt":
        commands = parse_make_tinymqtt(log_file)
        commands = clean_tinymqtt_commands(commands, llvm_pass_paths)
    elif project_name == "dnsmasq":
        commands = parse_make_dnsmasq(log_file)
        commands = clean_dnsmasq_commands(commands, llvm_pass_paths)
    elif project_name == "freecoap":
        commands = parse_make_freecoap(log_file)
        commands = clean_freecoap_commands(commands, llvm_pass_paths)
    elif project_name == "libcoap":
        commands = parse_make_libcoap(log_file)
        commands = clean_libcoap_commands(commands, llvm_pass_paths)  
    elif project_name == "pure-ftpd":
        commands = parse_make_pure_ftpd(log_file)
        commands = clean_pure_ftpd_commands(commands, llvm_pass_paths)
    elif project_name == "uftpd":
        commands = parse_make_log_uftpd(log_file)
        commands = clean_uftpd_commands(commands, llvm_pass_paths)
    elif project_name == "uftp":
        commands = parse_make_log_uFTP(log_file)
        commands = clean_uFTP_commands(commands, llvm_pass_paths)
    elif project_name == "dhcp":
        commands = parse_make_log_dhcp(log_file)
        commands = clean_dhcp_commands(commands, llvm_pass_paths)
    elif project_name == "ndhs":
        commands = parse_make_log_ndhs(log_file)
        commands = clean_ndhs_commands(commands, llvm_pass_paths)
    elif project_name == "tlse":
        commands = parse_make_log_tlse(log_file)
        commands = clean_tlse_commands(commands, llvm_pass_paths)
    elif project_name == "wolfssl":
        commands = parse_make_log_wolfssl(log_file)
        commands = clean_wolfssl_commands(commands, llvm_pass_paths)
    else:
        print(f"Unsupported project: {project_name}")
        sys.exit(1)

    
    save_commands(commands, output_file)
    save_command_script(commands, output_file, project_name)
    print(f"Extracted commands saved to {output_file}")
