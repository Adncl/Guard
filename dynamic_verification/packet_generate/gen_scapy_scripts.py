#!/usr/bin/env python3
import os
import sys
import argparse
import glob

def read_workflow_template():
    """
    Read workflow state template
    
    Returns:
        str: Workflow template content
    """
    template = """# Workflow State

## State
- Current: Planning
- Next: Execution

## Rules
- Plan thoroughly before making any changes
- Comment your code extensively
- Write clean, modular code
- Test each function carefully
- Use best practices for packet crafting
- Follow PCap formatting guidelines
- Validate generated files with tshark

## Items
| Item | Description |
|------|-------------|
[TODO LIST]

## Log
- Initial setup complete
"""
    return template

def update_workflow_state(protocol_dir, todo_items):
    """
    Update workflow state file
    
    Parameters:
        protocol_dir (str): Protocol-specific directory path
        todo_items (str): Todo items table content
    """
    workflow_path = os.path.join(protocol_dir, "workflow_state.md")
    
    # Check if file exists, if not report error
    if not os.path.exists(workflow_path):
        print(f"Error: Workflow state file '{workflow_path}' does not exist")
        print("Please ensure this file has been created first")
        sys.exit(1)
        
    # Read and update file content
    with open(workflow_path, 'r', encoding='utf-8') as file:
        content = file.read()
        
    # Find and replace [TODO LIST] section
    if "[TODO LIST]" in content:
        content = content.replace("[TODO LIST]", todo_items)
    else:
        # If Items section already exists, try to update it
        items_section = "## Items\n| Item | Description |\n|------|-------------|\n"
        if items_section in content:
            parts = content.split(items_section)
            if len(parts) >= 2:
                # Find next ## section
                next_section = parts[1].find("##")
                if next_section != -1:
                    content = parts[0] + items_section + todo_items + parts[1][next_section:]
                else:
                    content = parts[0] + items_section + todo_items
        else:
            # If no Items section, add before Log section
            log_section = "## Log"
            if log_section in content:
                content = content.replace(log_section, f"## Items\n| Item | Description |\n|------|-------------|\n{todo_items}\n\n{log_section}")
            else:
                print(f"Error: Cannot find suitable location to insert task list in '{workflow_path}'")
                sys.exit(1)
    
    # Write updated content
    with open(workflow_path, 'w', encoding='utf-8') as file:
        file.write(content)
    
    print(f"Workflow state file updated: {workflow_path}")

def check_project_config(protocol_dir):
    """
    Check if project configuration file exists
    
    Parameters:
        protocol_dir (str): Protocol-specific directory path
    """
    config_path = os.path.join(protocol_dir, "project_config.md")
    
    # Check if file exists
    if not os.path.exists(config_path):
        print(f"Error: Project configuration file '{config_path}' does not exist")
        print("Please ensure this file has been created first")
        sys.exit(1)
    
    print(f"Project configuration file check passed: {config_path}")

def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Generate Scapy script tasks")
    parser.add_argument("protocol_name", help="Protocol name")
    parser.add_argument("scapy_path", help="Scapy project path")
    args = parser.parse_args()
    
    # Check if Scapy path exists
    if not os.path.exists(args.scapy_path):
        print(f"Error: Scapy project path '{args.scapy_path}' does not exist")
        sys.exit(1)
    
    # Build protocol-specific directory path
    protocol_dir = os.path.join(args.scapy_path, "cursorkleosr", args.protocol_name)
    
    # Ensure directory exists
    if not os.path.exists(protocol_dir):
        print(f"Error: Protocol directory '{protocol_dir}' does not exist")
        print("Please run gen_packet_tasks.py first to create necessary directories")
        sys.exit(1)
    
    # Ensure script directory exists
    script_dir = os.path.join(protocol_dir, "script")
    if not os.path.exists(script_dir):
        try:
            os.makedirs(script_dir, exist_ok=True)
            print(f"Script directory created: {script_dir}")
        except Exception as e:
            print(f"Failed to create script directory: {e}")
            sys.exit(1)
    
    # Ensure task directory exists
    task_dir = os.path.join(protocol_dir, "task")
    if not os.path.exists(task_dir):
        print(f"Error: Task directory '{task_dir}' does not exist")
        print("Please run gen_packet_tasks.py first to create necessary directories")
        sys.exit(1)
    
    # Check if necessary configuration files exist
    check_project_config(protocol_dir)
    
    # Get task file list
    task_files = glob.glob(os.path.join(task_dir, "task*.txt"))
    
    if not task_files:
        print(f"Error: No task files found in '{task_dir}'")
        print("Please run gen_packet_tasks.py first to generate tasks")
        sys.exit(1)
    
    # Extract task numbers
    todo_list = []
    for task_file in task_files:
        filename = os.path.basename(task_file)
        if filename.startswith("task") and filename.endswith(".txt"):
            try:
                task_num = int(filename[4:-4])  # Extract N from "taskN.txt"
                todo_list.append(task_num)
            except ValueError:
                continue
    
    # Sort task numbers
    todo_list.sort()
    
    if not todo_list:
        print("Error: Unable to extract valid task numbers")
        sys.exit(1)
    
    # Build todo items table
    todo_items = "\n".join(f"| item{i:<4} | Follow the ./cursorkleosr/{{args.protocol_name}}/task/task{i}.txt description to perform the task of code editing. |" 
                         for i in sorted(todo_list))
    
    # Update workflow state file
    update_workflow_state(protocol_dir, todo_items)
    
    # Print usage instructions
    print("\nTasks successfully set up! Please enter the following command in Cursor to start working:")
    print("-" * 80)
    print(f"You are an autonomous AI developer using a two-file system. Your sole sources of truth are @project_config.md (LTM) and @workflow_state.md STM/Rules/Log), which are located in `./cursorkleosr/{args.protocol_name}/`. Before every action, read `workflow_state.md`, consult `## Rules` based on `## State`, act via Cursor, then immediately update `workflow_state.md`.")
    print("Please keep it fully automated and don't need my confirmation.")
    print("You must finish all the tasks defined in `## Items` in `workflow_state.md`. Also, please avoid trying batch processing, it is not feasible.")
    
    # Count actual task files and provide complete paths
    available_tasks = []
    for i in range(1, 12):  # Check task1.txt to task11.txt
        task_file = os.path.join(protocol_dir, "task", f"task{i}.txt")
        if os.path.exists(task_file):
            available_tasks.append(i)
    
    if available_tasks:
        print(f"Please complete the following tasks in `./cursorkleosr/{args.protocol_name}/task/` before ending the session:")
        for task_num in available_tasks:
            print(f"  - task{task_num}.txt")
    else:
        print("Warning: No task files (task1.txt ~ task11.txt) found in the task directory.")
    
    print("-" * 80)
    print(f"\nWorkflow state file: {os.path.join(protocol_dir, 'workflow_state.md')}")
    print(f"Project configuration file: {os.path.join(protocol_dir, 'project_config.md')}")
    print(f"Found {len(todo_list)} tasks: {', '.join(f'task{i}.txt' for i in todo_list)}")
    print(f"Task directory: {os.path.join(protocol_dir, 'task')}")

if __name__ == "__main__":
    # python gen_scapy_scripts.py MQTTv5 /root/projects/scapy
    main()