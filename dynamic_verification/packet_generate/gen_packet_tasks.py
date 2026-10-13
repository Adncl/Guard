#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import argparse
import time
import threading
import logging
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re

# Define LLM request timeout and retry configuration
LLM_REQUEST_TIMEOUT = 300  # Request timeout (seconds)
LLM_MAX_RETRIES = 3       # Maximum retry attempts
LLM_RETRY_DELAY = 5       # Retry wait time (seconds)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Reduce console output
logger.propagate = False
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Only show warnings and errors in console
logger.addHandler(console_handler)

def remove_think_tags(text):
    """
    Remove <think> and </think> tags and their contained content from string
    """
    return re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)

def clean_message_sequence(text):
    """
    Clean message sequence text, remove redundant marker symbols
    
    Parameters:
        text (str): Original response text
        
    Returns:
        str: Cleaned text
    """
    # Remove ``` markers wrapping message sequence
    text = re.sub(r'^```\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE)
    
    # Remove standalone ``` lines
    text = re.sub(r'^\s*```\s*$', '', text, flags=re.MULTILINE)
    
    return text.strip()

def fetch_rule_violations(db_path):
    """
    Read violation records from database
    
    Parameters:
        db_path (str): Database file path
        
    Returns:
        list: [(rule_desc, llm_response), ...] List of tuples containing rule descriptions and LLM responses
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            query = """
            SELECT rule_desc, llm_response 
            FROM rule_code_snippet 
            WHERE llm_response IS NOT NULL 
            AND llm_response != ''
            """
            cursor.execute(query)
            records = cursor.fetchall()
            
            # Filter records with result "violation found!"
            violations = []
            for rule_desc, llm_response in records:
                try:
                    if not rule_desc or not llm_response:
                        continue
                        
                    response_data = json.loads(llm_response)
                    if response_data.get("result") == "violation found!":
                        violations.append((rule_desc, llm_response))
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.warning(f"Error processing record: {e}")
                    continue
            
            return violations
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return []
    except Exception as e:
        logger.error(f"Unknown error: {e}")
        return []

def generate_message_sequence_prompt(protocol_name, rule_desc, violation_conclusion):
    """
    Generate prompt for LLM request
    
    Parameters:
        rule_desc (str): MQTT rule description
        violation_conclusion (str): Violation analysis conclusion
        
    Returns:
        str: Formatted prompt
    """
    prompt = """# Task
Based on `#Rule` and `#Violation Analysis`, generate a message sequence that violates the `#Rule` description for {protocol_name}, following the format in `#Requirements`.

# Rule
{rule_desc}

# Violation Analysis
{violation_conclusion}

# Requirements
1. Only contains messages sent from the Client to the Server, ensuring the sequence is complete, including all messages necessary before violation processing.
2. Only include necessary key fields (type, version, etc), fields and values directly related to `#Rule`, omit unrelated fields.
3. Each message follows this structure: `MessageName(key1=value1, key2=value2, ...)`
	Core rules:
	1. Message Name:
		- Indicates the message type name.
		- A text identifier before the parameter list.
		- Conventionally in ALL CAPS
	2. Parameter List:
		- Represents key fields and values for each message type.
		- Enclosed in parentheses `()` after the event name.
		- Can contain zero or more parameters.
		- If multiple parameters, separated by commas `,`.
	3. Parameters:
		- Each parameter is a `key=value` pair (e.g., `clientId="test-client"`).
		- Key: Parameter name, a text identifier (e.g., `clientId`, `protolevel`, `msgid`).
		- Value: Parameter data.
			- String values: Must be enclosed in double quotes `"` (e.g., `"test-client"`, `"$share/group+name/test/topic"`).
			- Numeric values: Written directly, without quotes (e.g., `5`, `1`, `0`).
4. Cover all possible scenarios described in the `Rule`, showing them independently; provide no more than 3 meaningful sequences in the format: "```#Sequence 1\n(message sequence)\n#Sequence 2\n(message sequence)\n```".
5. Omit any irrelevant content, avoid markdown formatting."""
    return prompt.format(protocol_name=protocol_name, rule_desc=rule_desc, violation_conclusion=violation_conclusion)

def generate_scapy_task_prompt(scapy_path, protocol_name, message_sequence, rule_desc="", task_index=1):
    """
    Generate prompt for Scapy script implementation
    
    Parameters:
        scapy_path (str): Scapy project path
        protocol_name (str): Protocol name
        message_sequence (str): Message sequence
        rule_desc (str, optional): Rule description
        task_index (int, optional): Task index, default is 1
        
    Returns:
        str: Formatted prompt
    """
    prompt = """#Task:
Please implement a Scapy script at `{scapy_path}` to generate {protocol_name} pcap files matching the `#Message Sequences`.

#Requirements:
1. For fields not mentioned in `#Message Sequences`, if mandatory, generate valid random values; if optional, omit them.
2. Ensure each message sequence occurs in a separate TCP connection from Client to Server, with each connection stored in a separate pcap file.
3. Avoid pcap file conflicts, implement and verify the script by running `cd {scapy_path}/test_case_generation && python3 xxx.py`, then validate with `tshark -r xxx.pcap -Y {protocol_name} -O {protocol_name}` until successful or after 5 attempts.
4. Ensure the generated scripts are located under ./cursorkleosr/{protocol_name}/script/, with each script named as script{task_index}.py where the index corresponds to its respective task number.

#Message Sequences
{message_sequence}"""
    
    if rule_desc:
        prompt += "\n\n#Rule\n{rule_desc}"
        
    return prompt.format(
        scapy_path=scapy_path,
        protocol_name=protocol_name,
        message_sequence=message_sequence,
        rule_desc=rule_desc,
        task_index=task_index
    )

def perform_llm_query(prompt):
    """
    Send request to LLM to get message sequence
    
    Parameters:
        prompt (str): Prompt
        
    Returns:
        str: LLM response content
    """
    # Use OpenAI library to send request
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from protocolguard.common import load_env
    load_env()
    api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('LLM_API_KEY', '')    # TODO: change to your own api key
    client = OpenAI(api_key=api_key, base_url=os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1"))   # TODO: change to your own base url

    # Send request with retry support
    for attempt in range(LLM_MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                # model="deepseek-r1-250120",  # Changed to actual model used
                model=os.getenv("PROTOCOLGUARD_MODEL", "deepseek-chat"),
                # model="deepseek-v3",
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )
            
            # Get response content
            if response and response.choices and len(response.choices) > 0:
                content = response.choices[0].message.content
                # First remove think tags, then clean message sequence markers
                content = remove_think_tags(content)
                content = clean_message_sequence(content)
                print(f"LLM response: {content}")
                return content
            return ""
            
        except Exception as e:
            logger.warning(f"Request failed (attempt {attempt+1}/{LLM_MAX_RETRIES}): {e}")
            if attempt < LLM_MAX_RETRIES - 1:
                time.sleep(LLM_RETRY_DELAY)
            else:
                logger.error("Maximum retry attempts reached, abandoning request")
    
    return ""

def initialize_protocol_directories(scapy_path, protocol_name):
    """
    Initialize protocol-related directories
    
    Parameters:
        scapy_path (str): Scapy project path
        protocol_name (str): Protocol name
    """
    # Ensure cursorkleosr directory exists
    cursorkleosr_dir = os.path.join(scapy_path, "cursorkleosr")
    os.makedirs(cursorkleosr_dir, exist_ok=True)
    
    # Ensure protocol-specific directory exists
    protocol_dir = os.path.join(cursorkleosr_dir, protocol_name)
    os.makedirs(protocol_dir, exist_ok=True)
    
    # Ensure task directory exists
    task_dir = os.path.join(protocol_dir, "task")
    os.makedirs(task_dir, exist_ok=True)
    
    # Check if md files need to be copied
    current_dir = os.path.dirname(os.path.abspath(__file__))
    source_cursorkleosr_dir = os.path.join(current_dir, "cursorkleosr")
    
    if os.path.exists(source_cursorkleosr_dir):
        # Copy project configuration file
        source_project_config = os.path.join(source_cursorkleosr_dir, "project_config.md")
        target_project_config = os.path.join(protocol_dir, "project_config.md")
        
        if os.path.exists(source_project_config) and not os.path.exists(target_project_config):
            import shutil
            shutil.copy2(source_project_config, target_project_config)
            logger.info(f"Project configuration file copied to: {target_project_config}")
        
        # Copy workflow state file
        source_workflow_state = os.path.join(source_cursorkleosr_dir, "workflow_state.md")
        target_workflow_state = os.path.join(protocol_dir, "workflow_state.md")
        
        if os.path.exists(source_workflow_state) and not os.path.exists(target_workflow_state):
            import shutil
            shutil.copy2(source_workflow_state, target_workflow_state)
            logger.info(f"Workflow state file copied to: {target_workflow_state}")
    
    return protocol_dir

def process_violation(args, protocol_name, rule_desc, violation_json, task_index):
    """
    Process a single violation record
    
    Parameters:
        args: Command line arguments
        rule_desc (str): Rule description
        violation_json (str): Violation JSON
        task_index (int): Task index
        
    Returns:
        bool: Whether processing was successful
    """
    try:
        # Ensure rule_desc and violation_json are not empty
        if not rule_desc:
            logger.error(f"Task {task_index}: rule_desc parameter is empty")
            return False
            
        if not violation_json:
            logger.error(f"Task {task_index}: violation_json parameter is empty")
            return False
            
        # Generate message sequence prompt
        sequence_prompt = generate_message_sequence_prompt(protocol_name, rule_desc, violation_json)
        
        # Request LLM to generate message sequence
        logger.info(f"Requesting LLM to generate message sequence (Task {task_index})...")
        message_sequence = perform_llm_query(sequence_prompt)
        
        if not message_sequence:
            logger.error(f"Task {task_index}: Unable to get LLM response")
            return False
        
        # Generate Scapy implementation task prompt
        task_prompt = generate_scapy_task_prompt(args.scapy_path, args.protocol_name, message_sequence, rule_desc, task_index)
        
        # Get task directory path (now protocol-specific)
        protocol_dir = os.path.join(args.scapy_path, "cursorkleosr", args.protocol_name)
        task_dir = os.path.join(protocol_dir, "task")
        
        # Write task file
        task_file = os.path.join(task_dir, f"task{task_index}.txt")
        with open(task_file, "w", encoding="utf-8") as f:
            f.write(task_prompt)
        
        logger.info(f"Successfully generated task file: {task_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error processing violation record (Task {task_index}): {e}")
        return False

def main():
    """Main function"""
    # Parse command line arguments
    # python3 gen_mqtt_packet_tasks.py MQTTv5 /root/projects/scapy /root/llvm-pass-project/sqlite_mosquitto.db
    # python3 gen_mqtt_packet_tasks.py CoAP /root/projects/scapy /root/llvm-pass-project/sqlite_FreeCoAP.db
    parser = argparse.ArgumentParser(description="Generate MQTT violation message sequence tasks")
    parser.add_argument("protocol_name", help="Protocol name")
    parser.add_argument("scapy_path", help="Scapy project path")
    parser.add_argument("db_path", help="Database path")
    parser.add_argument("--threads", type=int, default=16, help="Number of threads (default: 16)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed logs")
    args = parser.parse_args()
    
    # If verbose mode is specified, adjust log level
    if args.verbose:
        console_handler.setLevel(logging.INFO)
    
    print(f"Starting to process {args.protocol_name} protocol violation records...")
    
    # Check if database file exists
    if not os.path.exists(args.db_path):
        print(f"Error: Database file '{args.db_path}' does not exist")
        sys.exit(1)
    
    # Check if Scapy path exists
    if not os.path.exists(args.scapy_path):
        print(f"Error: Scapy project path '{args.scapy_path}' does not exist")
        sys.exit(1)
    
    # Initialize protocol directory structure and copy necessary files
    initialize_protocol_directories(args.scapy_path, args.protocol_name)
    
    # Get violation records from database
    print(f"Reading violation records from database {args.db_path}...")
    violations = fetch_rule_violations(args.db_path)
    print(f"Found {len(violations)} violation records")
    
    if not violations:
        print("No violation records found to process, exiting")
        sys.exit(0)
    
    # Disable tqdm output in multi-threading
    tqdm.monitor_interval = 0
    
    # Use thread pool to process violation records
    successful_tasks = 0
    failed_tasks = 0
    task_results = {}
    
    print(f"Starting to process {len(violations)} violation records using {min(args.threads, len(violations))} threads...")
    
    with ThreadPoolExecutor(max_workers=min(args.threads, len(violations))) as executor:
        futures = {}
        for i, (rule_desc, violation_json) in enumerate(violations, 1):
            future = executor.submit(
                process_violation, 
                args, 
                args.protocol_name,
                rule_desc, 
                violation_json, 
                i
            )
            futures[future] = i
        
        # Use simple progress bar, reduce frequent printing
        with tqdm(total=len(futures), desc="Processing progress", disable=not args.verbose) as pbar:
            for future in as_completed(futures):
                task_index = futures[future]
                try:
                    task_results[task_index] = future.result()
                    if task_results[task_index]:
                        successful_tasks += 1
                    else:
                        failed_tasks += 1
                except Exception as e:
                    task_results[task_index] = False
                    failed_tasks += 1
                    logger.error(f"Task {task_index} failed: {e}")
                finally:
                    pbar.update(1)
    
    # Print summary information after processing is complete
    print(f"\nProcessing complete! Success: {successful_tasks}, Failed: {failed_tasks}, Total: {len(violations)}")
    
    # If there are failed tasks, print the failed task indices
    if failed_tasks > 0:
        failed_indices = [idx for idx, result in task_results.items() if not result]
        print(f"Failed task indices: {', '.join(map(str, sorted(failed_indices)))}")
    
    print(f"Task files saved to: {os.path.join(args.scapy_path, 'cursorkleosr', args.protocol_name, 'task')}")

if __name__ == "__main__":
    main()