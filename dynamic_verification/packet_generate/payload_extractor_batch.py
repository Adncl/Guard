#!/usr/bin/python3

import argparse
import os
import subprocess
import sys
import glob

def main():
    parser = argparse.ArgumentParser(description="Batch process PCAP files to extract application payloads.")
    parser.add_argument('--input-dir', required=True, help="Directory containing PCAP files.")
    parser.add_argument('--output-dir', required=True, help="Directory to save extracted .raw payload files.")
    parser.add_argument('--server-port', type=int, required=True, help="Server port number for the payload extractor script.")
    parser.add_argument('--client-port', type=int, help="Optional: Client port number for the payload extractor script.")
    parser.add_argument('--direction', choices=['both', 'to-server', 'from-server', 'to-client'], 
                        default='to-server', help="Data direction to capture: 'both' (default), 'to-server' (client->server), 'from-server' (server->client)")
    parser.add_argument('--script-path', default=os.path.join(os.path.dirname(__file__), "payload_extractor.py"),
                        help="Path to the 'payload_extractor.py' script. Defaults to 'payload_extractor.py' in the current directory or PATH.")

    args = parser.parse_args()

    # Validate input directory
    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' not found or is not a directory.")
        sys.exit(1)

    # Validate or create output directory
    if not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
            print(f"Created output directory: '{args.output_dir}'")
        except OSError as e:
            print(f"Error: Could not create output directory '{args.output_dir}': {e}")
            sys.exit(1)
    elif not os.path.isdir(args.output_dir):
        print(f"Error: Output path '{args.output_dir}' exists but is not a directory.")
        sys.exit(1)
        
    # Validate script_path (basic check if it exists if it's not just a name for PATH lookup)
    if os.path.sep in args.script_path and not os.path.isfile(args.script_path):
        print(f"Error: Payload extractor script '{args.script_path}' not found.")
        sys.exit(1)


    pcap_files = []
    # Common PCAP extensions
    extensions = ['*.pcap', '*.pcapng', '*.cap'] 
    for ext in extensions:
        pcap_files.extend(glob.glob(os.path.join(args.input_dir, ext)))
    
    # Sort for consistent processing order (optional, but good for reproducibility)
    pcap_files.sort()

    if not pcap_files:
        print(f"No PCAP files found in '{args.input_dir}' with extensions {extensions}.")
        sys.exit(0)

    print(f"Found {len(pcap_files)} PCAP file(s) to process.")
    seed_index = 0
    processed_count = 0
    failed_count = 0

    for pcap_file_path in pcap_files:
        seed_index += 1
        base_pcap_name = os.path.basename(pcap_file_path)
        output_filename = f"seed_{seed_index}.raw"
        output_filepath = os.path.join(args.output_dir, output_filename)

        command = [
            sys.executable,  # Use the current Python interpreter
            args.script_path,
            '--input', pcap_file_path,
            '--server-port', str(args.server_port),
            '--output', output_filepath
        ]

        if args.client_port is not None:
            command.extend(['--client-port', str(args.client_port)])
        
        command.extend(['--direction', args.direction])

        print(f"\nProcessing '{base_pcap_name}' ({seed_index}/{len(pcap_files)}) -> '{output_filepath}'...")
        
        try:
            # Run the payload_extractor.py script
            result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8')

            if result.stdout:
                print("--- Script Output ---")
                print(result.stdout.strip())
            if result.stderr:
                print("--- Script Error Output ---", file=sys.stderr)
                print(result.stderr.strip(), file=sys.stderr)
            
            if result.returncode == 0:
                print(f"Successfully processed '{base_pcap_name}'.")
                # Check if the output file was actually created and has content,
                # as the script might run successfully but not extract data.
                if os.path.exists(output_filepath) and os.path.getsize(output_filepath) > 0:
                    processed_count += 1
                elif os.path.exists(output_filepath): # File exists but is empty
                    print(f"Warning: Output file '{output_filepath}' was created but is empty.")
                    # Consider if empty files should count as success or partial failure
                    processed_count +=1 # Counting it as processed if script exited 0
                else: # Script exited 0 but no output file
                    print(f"Warning: Output file '{output_filepath}' was not created by the script, though it exited successfully.")
                    failed_count += 1 # Or handle as a specific type of non-success
                    
            else:
                print(f"Error: Script failed for '{base_pcap_name}' with exit code {result.returncode}.")
                failed_count += 1

        except FileNotFoundError:
            print(f"Fatal Error: The payload extractor script '{args.script_path}' was not found. Please check the --script-path argument.")
            sys.exit(1)
        except Exception as e:
            print(f"An unexpected error occurred while trying to run the script for '{base_pcap_name}': {e}")
            failed_count += 1

    print("\n--- Batch Processing Summary ---")
    print(f"Total PCAP files found: {len(pcap_files)}")
    print(f"Successfully processed (output file potentially created): {processed_count}")
    print(f"Failed or produced no output: {failed_count}")
    print(f"Output files are located in: '{os.path.abspath(args.output_dir)}'")

if __name__ == "__main__":
    main()