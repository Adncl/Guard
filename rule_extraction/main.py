# protocolProject/main.py
import argparse
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list, cwd: str = None):
    """Universal command execution function"""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        print(f"[SUCCESS] Command executed successfully: {' '.join(cmd)}")
        if result.stdout:
            print("Output summary:\n" + "\n".join(result.stdout.splitlines()[:5]))
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Command execution failed: {' '.join(e.cmd)}")
        print(f"Error message:\n{e.stdout}")
        sys.exit(1)


def main():
    # Parameter parsing
    parser = argparse.ArgumentParser(
        description="Protocol Analysis Full Process Management System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True, help="Protocol name (e.g., MQTT, HTTP)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 5.0, 1.1)")
    parser.add_argument("--html-file", required=True,
                        help="Original HTML file path (relative to current directory)")
    args = parser.parse_args()

    # Verify HTML file exists
    html_path = Path(args.html_file)
    if not html_path.exists():
        print(f"❌ HTML file does not exist: {html_path.absolute()}")
        sys.exit(1)

    # Define execution commands for each stage
    steps = [
        {
            "name": "Document Processing Stage",
            "cmd": [
                sys.executable, "-m", "documentProcess",
                "--api-key", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version,
                "--html-file", str(html_path.absolute())
            ],
            "cwd": None  # Execute in root directory
        },
        {
            "name": "Keyword Processing Stage",
            "cmd": [
                sys.executable, "-m", "keywordProcess",
                "--apikey", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version
            ],
            "cwd": None
        },
        {
            "name": "Rule Processing Stage",
            "cmd": [
                sys.executable, "__main__.py",
                "--apikey", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version
            ],
            "cwd": "ruleProcess"  # Need to execute in subdirectory
        }
    ]

    # Execute each stage sequentially
    for step in steps:
        print(f"\n{'=' * 40}")
        print(f"🚀 Starting {step['name']}")
        print(f"📂 Working directory: {step['cwd'] or 'Current directory'}")
        print(f"⚙️ Executing command: {' '.join(step['cmd'])}")
        print("=" * 40)

        run_command(
            cmd=step["cmd"],
            cwd=step["cwd"]
        )

    print("\n✅ All processes completed!")


if __name__ == "__main__":
    main()