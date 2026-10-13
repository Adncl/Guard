# main.py
import argparse
import subprocess
import sys
from pathlib import Path


def get_module_path(script_name: str) -> str:
    """Get absolute path of script within module"""
    current_dir = Path(__file__).parent  # Directory where main.py is located
    script_path = current_dir / f"{script_name}.py"

    if not script_path.exists():
        print(f"❌ Error: Cannot find {script_name}.py file")
        print(f"Please confirm file exists at: {script_path}")
        sys.exit(1)

    return str(script_path)

def main():
    parser = argparse.ArgumentParser(description="Universal Protocol Rule Analysis System", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--apikey", help="DeepSeek API Key (required for second and third stages)")
    parser.add_argument("--protocol", required=True, help="Target protocol name (e.g., HTTP, MQTT)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 1.1, 5.0)")
    parser.add_argument("--steps", nargs="+",
                       choices=["all", "first", "second", "third"],
                       default=["all"],
                       help="Select steps to execute (default: all)")
    args = parser.parse_args()

    # Step processing logic
    steps = args.steps
    if "all" in steps:
        steps = ["first", "second", "third"]

    # Execute first stage
    if "first" in steps:
        print("\n🚀 Executing first stage: Basic rule filtering")
        first_script = get_module_path("first_rule")
        subprocess.run([sys.executable, first_script], check=True)

    # Execute second stage
    if "second" in steps:
        if not args.apikey:
            raise ValueError("Second stage requires API key!")
        print("\n🔍 Executing second stage: AI rule validation")
        second_script = get_module_path("second_rule")
        subprocess.run([
            sys.executable, second_script,
            "--apikey", args.apikey,
            "--protocol", args.protocol,
            "--version", args.version
        ], check=True)

    # Execute third stage
    if "third" in steps:
        if not args.apikey:
            raise ValueError("Third stage requires API key!")
        print("\n🎯 Executing third stage: Protocol field parsing")
        third_script = get_module_path("third_rule")
        subprocess.run([
            sys.executable, third_script,
            "--apikey", args.apikey,
            "--protocol", args.protocol,
            "--version", args.version
        ], check=True)

if __name__ == "__main__":
    main()