import re
import argparse

def parse_wpa_report(input_file, output_file, filter_headers=True):
    in_fp_section = False
    pattern = re.compile(r'CallSite:.*\{ "ln": (\d+), "cl": (\d+), "fl": "([^"]+)" \}.*')
    target_pattern = re.compile(r'^\s*(\S+)')
    
    with open(input_file, 'r', encoding='utf-8') as f_in, open(output_file, 'w', encoding='utf-8') as f_out:
        for line in f_in:
            if "Function Pointer Targets" in line:
                in_fp_section = True
            elif in_fp_section:
                match = pattern.search(line)
                if match:
                    ln, cl, fn = match.groups()
                    
                    # Check if it's a .h file and decide whether to skip based on filter_headers parameter
                    if filter_headers and fn.endswith('.h'):
                        continue
                    
                    # Check if current line contains target function names
                    if "with Targets:" in line:
                        # Read subsequent lines to get all target function names
                        while True:
                            target_line = next(f_in, '').strip()
                            if not target_line:  # If empty line is encountered, stop reading
                                break
                            
                            func_match = target_pattern.search(target_line)
                            if func_match:
                                func_name = func_match.group(1)
                                f_out.write(f"{fn}:{ln} {func_name}\n")

def main():
    # (1) ~/SVF-SVF-2.9/build/bin/wpa -print-fp -ander demo.bc > fp.txt
    # (2) python3 /root/llvm-pass-project/indirect_callgraph.py ./fp.txt ./ffp.txt --include-headers(optional)
    parser = argparse.ArgumentParser(description='Parse WPA report and extract function pointer targets.')
    parser.add_argument('input_file', type=str, help='Path to the input txt file')
    parser.add_argument('output_file', type=str, help='Path to the output txt file')
    parser.add_argument('--include-headers', action='store_true', 
                        help='Include results from header (.h) files (default: filtered out)')
    args = parser.parse_args()
    
    # Decide whether to filter header files based on command line arguments
    filter_headers = not args.include_headers
    parse_wpa_report(args.input_file, args.output_file, filter_headers)

if __name__ == "__main__":
    main()