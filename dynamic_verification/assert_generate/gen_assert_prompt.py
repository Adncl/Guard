import os
import sqlite3
import json
import sys
from tqdm import tqdm
import argparse
import shutil


def fetch_rule_code_llmresponse_record(db_path):
    """
    Read records from the rule_code_snippet table in the database
    Returns: list of tuples (rule_desc, code_snippet, call_graph, llm_response)
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rule_desc, code_snippet, call_graph, llm_response FROM rule_code_snippet WHERE llm_response IS NOT NULL AND llm_response != ''")
            all_records = cursor.fetchall()
            return all_records
    except sqlite3.DatabaseError as e:
        print(f"Database error: {e}")
        return []
    except Exception as e:
        print(f"Unknown error: {e}")
        return []

# -------------------- Data Processing Operations --------------------
def extract_function_source_code(llm_response):
    """
    Extract violation functions from LLM response and get their source code
    
    Parameters:
        llm_response (str): JSON format response returned by LLM
    
    Returns:
        str: String containing source code of all related functions
    """
    try:
        # Parse JSON response
        response_data = json.loads(llm_response)
        result_code = ""
        
        # Check if violation is found
        if response_data.get("result") == "violation found!":
            violations = response_data.get("violations", [])
            function_content = {}  # Store file path and function code range
            
            print(f"Extracting source code for {len(violations)} violation functions...")
            
            # Iterate through each violation record
            for violation in violations:
                function_name = violation.get("function_name")
                filename = violation.get("filename")
                
                if not function_name or not filename:
                    continue
                
                # Initialize dictionary for each file
                if filename not in function_content:
                    function_content[filename] = {}
                
                # Construct AST file path
                directory = os.path.dirname(filename)
                base_name_noext = os.path.splitext(os.path.basename(filename))[0]
                json_path = directory + "/.cf_" + base_name_noext + ".json"
                print(f"Processing file: {filename}, function: {function_name}, AST path: {json_path}")
                
                # Read AST file to get function range
                if os.path.exists(json_path):
                    with open(json_path, 'r') as json_file:
                        json_data = json.load(json_file)
                        for func_info in json_data.get("functions", []):
                            if func_info["name"] == function_name:
                                start = func_info["overall"]["start"]
                                end = func_info["overall"]["end"]
                                function_content[filename][function_name] = (start, end)
                                break
            
            # Extract source code based on obtained function ranges
            for file_path, functions in function_content.items():
                for func_name, (start, end) in functions.items():
                    function_source = get_function_code(file_path, start, end)
                    result_code += function_source + "\n\n"
            
        return result_code
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return ""
    except Exception as e:
        print(f"Error occurred while extracting function source code: {e}")
        return ""

def get_function_code(file_path, start, end):
    """
    Extract code snippet based on file path and line number range, and format output.
    
    Parameters:
        file_path (str): Source code file path, may contain line numbers (e.g., /path/to/file.c:130)
        start (int): Starting line number (inclusive).
        end (int): Ending line number (inclusive).
    
    Returns:
        str: Formatted code snippet string.
    """
    try:
        # Check if file path contains line numbers, remove if present
        import re
        file_path = re.sub(r':\d+$', '', file_path)
            
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        # Initialize result string
        function_source = ""
        
        # Iterate through each line of the file
        for current_line, line in enumerate(lines, start=1):
            if start <= current_line <= end:
                # Right-align line number to 5 character width, concatenate line number and code content
                function_source += f"{current_line:>5}: {line}"
            elif current_line > end:
                break  # Exit loop early after exceeding end line number
        
        return function_source
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return ""
    except Exception as e:
        print(f"Error occurred while reading file: {e}")
        return ""

def generate_function_code(function_dict):
    """
    Generate formatted function code based on function dictionary
    
    Parameters:
        function_dict (dict): Key is filename, value is dictionary containing function name and position information
        
    Returns:
        str: Formatted function code
    """
    # Fix: function_dict structure should be {filename: {func_name: (start, end)}}
    function_code = ""
    for file_path, func_info in function_dict.items():
        for func_name, (start, end) in func_info.items():
            function_source = get_function_code(file_path, start, end)
            function_code += f"Function: {func_name}\n"
            function_code += f"Path: {file_path}\n"
            function_code += function_source
    
    return function_code

def generate_agent_prompt(rule_desc, previous_response, code_snippet, compile_command):
    """
    Generate Agent prompt
    
    Parameters:
        rule_desc (str): Rule description
        previous_response (str): Previous LLM response
        code_snippet (str): Code snippet
        compile_command (str): Compilation command
        
    Returns:
        str: Generated prompt
    """
    prompt_template = """# Task
Analyze the protocol rule logic in `#Rule` and combine it with the summary of missing function logic identified in `#PreviousResponse` for comprehensive evaluation. 
Generate a corresponding ASSERT statement for the missing logic in that function. Determine the optimal insertion position for this ASSERT statement in the `#Code` snippet.

# Task Steps
1. Parse the content described in `#Rule` to extract key conditions or constraints.
2. Analyze the execution logic of the function in `#Code` and identify the missing logic based on `#PreviousResponse`.
3. Generate a syntactically correct ASSERT statement for the missing logic:
    - Follow the descriptions in `## Key Constraints` and `## Critical Patterns & Conventions` in `cursorkleosr/project_config.md`.
    - The purpose of the ASSERT statement is to actively terminate program execution when the program is in a scenario that **should have been handled by the missing logic**, not to patch the missing logic.
    - If there are variables in the `Code` that can be tracked by the ASSERT statement, prioritize those closest to the original data packet rather than those that have been processed.
    - If the condition for judging "whether the program state is correct" (i.e., whether to trigger the missing logic scenario) is complex, please define a helper function (usually returning a boolean value) to encapsulate this judgment logic.
    - The ASSERT statement should be implemented in the following format and must contain the conditional compilation instruction and the error message: `#ifdef ASSERT_ENABLED\\nassert(function(xxx) || !"rule desc");\\n#endif`.
4. Determine the optimal insertion position for the ASSERT statement:
    - The ASSERT statement is designed to detect and block at the point where "an error is about to occur", allowing developers to collect the current input for subsequent reproduction.
    - if conditions permit, prioritize selecting lines close to the problematic code (e.g., function entry, before conditional judgment).
    - Check if the current file needs to include relevant standard header files (e.g., assert.h).
5. If a custom function is implemented, determine the insertion position for the function definition and declaration:
    - The function name must start with `assert_related_` to avoid naming conflicts.
    - The definition and declaration of the custom function must be wrapped in the conditional compilation block, i.e., `#ifdef ASSERT_ENABLED\\nvoid assert_related_...\\n#endif`.
6. After completing the task, call the command-line tool to verify the generated result.
    - Command reference: `[compile_command]`.

# Rule: 
[rule_desc]

# PreviousResponse:
[previous_response]

# Code:
[relevant_code]
"""
    # Replace placeholders
    prompt = prompt_template.replace("[rule_desc]", rule_desc)
    prompt = prompt.replace("[relevant_code]", code_snippet)
    prompt = prompt.replace("[previous_response]", previous_response)
    prompt = prompt.replace("[compile_command]", compile_command)
    return prompt

def write_agent_prompt_to_file(project_path, prompt, file_index):
    """
    Write prompt to file
    
    Parameters:
        project_path (str): Project path
        prompt (str): Prompt content
        file_index (int): File index
    """
    file_name = f"rule{file_index}.txt"
    project_path += "/cursorkleosr/task"
    if not os.path.exists(project_path):
        os.makedirs(project_path)

    file_path = os.path.join(project_path, file_name)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(prompt)
    print(f"Prompt saved to: {file_path}")

def initialize_cursorkleosr(project_path):
    '''
    1. Copy the ./cursorkleosr directory and all its internal files from the current script's file path to the project_path, overwriting if it already exists
    '''
    
    # Get the directory where the current script is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Source directory path
    source_dir = os.path.join(current_dir, 'cursorkleosr')
    
    # Target directory path
    target_dir = os.path.join(project_path, 'cursorkleosr')
    
    # If source directory exists
    if os.path.exists(source_dir):
        # If target directory already exists, remove it
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        
        # Copy entire directory and its contents
        shutil.copytree(source_dir, target_dir)
        print(f"Copied cursorkleosr directory to: {target_dir}")
    else:
        print(f"Warning: Source directory {source_dir} does not exist")

def write_todo_list(todo_list, project_path):
    """
    Write task list to workflow_state.md file, replacing the [TODO LIST] section
    
    Parameters:
        todo_list (list): Task number list, e.g., [1, 2, 3]
        project_path (str): Project path
    """
    workflow_path = os.path.join(project_path, 'cursorkleosr', 'workflow_state.md')
    
    try:
        # Read file content
        with open(workflow_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Build new task list content
        todo_items = "\n".join(f"| item{i:<4} | Follow the ./cursorkleosr/task/rule{i}.txt description to perform the task of code editing. |" 
                             for i in sorted(todo_list))

        # Replace [TODO LIST] section
        new_content = content.replace('[TODO LIST]', f'{todo_items}\n')
        
        # Write back to file
        with open(workflow_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
            print(new_content)
            
        print(f"Task list updated to: {workflow_path}")
        
    except FileNotFoundError:
        print(f"Error: File does not exist: {workflow_path}")
    except Exception as e:
        print(f"Error occurred while writing task list: {e}")
        
def main(db_path, compile_command, output_dir):
    """
    Main function: Extract violation records and generate Agent prompts
    
    Parameters:
        db_path (str): Database path
        compile_command (str): Compilation command
        output_dir (str): Output directory
    """
    # Check if database file exists
    if not os.path.exists(db_path):
        print(f"Error: Database file '{db_path}' does not exist")
        sys.exit(1)
        
    # Read all results from database
    print(f"Reading records from database {db_path}...")
    all_records = fetch_rule_code_llmresponse_record(db_path)
    print(f"Reading complete, obtained {len(all_records)} records")
    
    violation_count = 0
    generated_count = 1
    todo_list = []  # Used to collect generated prompt file numbers
    
    # Use tqdm to show processing progress
    for rule_desc, code_snippet, _, llm_response in tqdm(all_records, desc="Processing records"):
        try:
            # Parse JSON string
            response_data = json.loads(llm_response)
            
            # Check if result is "violation found!"
            if response_data.get("result") != "violation found!":
                continue
                
            violation_count += 1
            
            # Extract function names and source code files
            function_code = extract_function_source_code(llm_response)
            
            # Generate Agent prompt
            agent_prompt = generate_agent_prompt(rule_desc, llm_response, function_code or code_snippet, compile_command)
            
            # Write to file
            write_agent_prompt_to_file(output_dir, agent_prompt, generated_count)
            todo_list.append(generated_count)  # Record generated prompt file number
            generated_count += 1
            
        except json.JSONDecodeError:
            print(f"Warning: Record #{violation_count} contains invalid JSON format")
        except Exception as e:
            print(f"Error occurred while processing record: {e}")
    
    print(f"Processing complete! Found {violation_count} violations, generated {len(todo_list)} prompt files to {output_dir}/cursorkleosr/task")

    # Update TODO LIST in workflow_state.md
    if todo_list:
        write_todo_list(todo_list, output_dir)
    
    # Print final guidance information
    if todo_list:
        task_list = ", ".join([f"task{i}.txt" for i in sorted(todo_list)])
        print("\n" + "="*80)
        print("You are an autonomous AI developer using a two-file system. Your sole sources of truth are @project_config.md (LTM) and @workflow_state.md (STM/Rules/Log), which are located in `./cursorkleosr/`. Before every action, read `workflow_state.md`, consult `## Rules` based on `## State`, act via Cursor, then immediately update `workflow_state.md`.")
        print(f"MUST complete all the following tasks in `./cursorkleosr/task/` before ending the session:")
        print(f"  - {task_list}")
        print("Processing MUST be done one-by-one (no batch processing allowed, as it is unfeasible), fully automated, and require no manual confirmation.")
        print("="*80)

if __name__ == "__main__":
    # python3 /root/llvm-pass-project/violation_check/gen_assert_prompt.py --db_path /root/llvm-pass-project/sqlite_FreeCoAP.db --output_dir /root/projects/FreeCoAP --compile_command "cd /root/projects/FreeCoAP && make CFLAGS=\"-g -O0 -DASSERT_ENABLED=1\""
    parser = argparse.ArgumentParser(description='Process violation checks and generate Agent prompts')
    parser.add_argument('--db_path', required=True, help='SQLite database file path')
    parser.add_argument('--output_dir', required=True, help='Project path')
    parser.add_argument('--compile_command', required=True, help='Project compilation command')
    
    args = parser.parse_args()
    
    # Check if output directory exists, warn and terminate if not
    if not os.path.exists(args.output_dir):
        print(f"Error: Output directory '{args.output_dir}' does not exist, please create it first")
        sys.exit(1)
    
    initialize_cursorkleosr(args.output_dir)
    # Call main function
    main(args.db_path, args.compile_command, args.output_dir)

