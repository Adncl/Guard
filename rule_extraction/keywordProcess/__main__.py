import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List


class KeywordProcessor:
    def __init__(self, apikey: str, protocol: str, version: str):
        self.apikey = apikey
        self.protocol = protocol
        self.version = version
        self.project_root = Path(__file__).parent.parent
        self.keyword_dir = Path(__file__).parent / "directoryStore"

        self.keyword_dir.mkdir(exist_ok=True, parents=True)

        self.path_config = {
            "input_json": self.project_root / "documentProcess/directoryStore/filtered_headings.json",
            "specify_txt": self.project_root / "documentProcess/directoryStore/specify_keywords.txt",
            "config_file": self.keyword_dir / "config.json",
            "keyword_list": self.keyword_dir / "keyword_list.json",
            "paragraph_output": self.keyword_dir / "paragraphs_output.json"
        }

    def _create_default_config(self):
        default_config = {
            "api_settings": {
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-chat"
            },
            "processing": {
                "keyword_sources": ["txt"]
            },
            "paths": {
                "specify_keywords": "documentProcess/directoryStore/specify_keywords.txt",
                "input_json": "documentProcess/directoryStore/filtered_headings.json",
                "keyword_list": "keywordProcess/directoryStore/keyword_list.json",
                "paragraph_output": "./directoryStore/paragraphs_output.json",
                "specify_output": "./directoryStore/specify_keywords_update_r1.json",
                "modal_output": "./directoryStore/modal_keywords_update_r1.json",
                "comparative_output": "./directoryStore/comparative_keywords_update_r1.json",
                "final_output": "./directoryStore/keywords_final.json"
            },
            "filters": {
                "specify": ["Client", "client", "Server", "server", "Session", "Network Connection", "message"],
                "comparative": ["is", "are", "not", "use", "send", "sending", "meet", "receive", "MUST", "uses"]
            }
        }
        with open(self.path_config["config_file"], "w") as f:
            json.dump(default_config, f, indent=2)
        print(f"✅ A default configuration file has been created: {self.path_config['config_file']}")

    def validate_paths(self):
        required_files = [
            self.path_config["input_json"],
            self.path_config["specify_txt"]
        ]

        if not self.path_config["config_file"].exists():
            print("⚠️ No configuration file was found")
            self._create_default_config()

        missing = [str(p) for p in required_files if not p.exists()]
        if missing:
            print("❌ Missing necessary input file:")
            print("\n".join(missing))
            sys.exit(1)

        try:
            with open(self.path_config["config_file"], "r") as f:
                config = json.load(f)
            assert "processing" in config, "Configuration is missing the 'processing' field."
            assert isinstance(config["processing"]["keyword_sources"], List), "The keyword_sources should be a list."
        except Exception as e:
            print(f"❌ Error in the configuration file: {str(e)}")
            sys.exit(1)

    def run_step(self, script_name: str, needs_key: bool = False):
        script_path = Path(__file__).parent / f"{script_name}.py"
        if not script_path.exists():
            print(f"❌ The processing script was not found: {script_path.name}")
            sys.exit(1)

        cmd = [sys.executable, str(script_path)]
        if script_name in ["keywords", "specify_keywords_update", "comparative_keywords_updates", "keywords_final"]:
            cmd += ["--protocol", self.protocol, "--version", self.version]
        if needs_key:
            cmd += ["--apikey", self.apikey]

        print(f"\n🚀 It's in progress {script_name.upper()}...")
        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print(f"✅ {script_name} Successful execution")
            if result.stdout:
                print(f"{result.stdout[:200]}...")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ {script_name} Failure to execute (code={e.returncode})")
            print("Error details:\n", e.stderr)
            sys.exit(1)

    def execute(self):
        print("🔍 Begin the validation of the system...")
        self.validate_paths()

        processing_steps = [
            ("keywords", False),
            ("specify_keywords_update", True),
            ("modal_keywords_update", True),
            ("comparative_keywords_updates", True),
            ("keywords_final", True)  
        ]

        print("\n⚙️ Start the processing flow")
        for step, needs_key in processing_steps:
            if not self.run_step(step, needs_key):
                sys.exit(1)

        print("\n🎉 Processing completed! Result files:")
        print(f" - Keyword list: {self.path_config['keyword_list']}")
        print(f" - Reorganized paragraphs: {self.path_config['paragraph_output']}")


def main():
    parser = argparse.ArgumentParser(
        description="Universal Protocol Keyword Processing System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True, help="Target protocol name (e.g., HTTP/MQTT)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 1.1/5.0)")
    args = parser.parse_args()

    processor = KeywordProcessor(
        apikey=args.apikey,
        protocol=args.protocol,
        version=args.version
    )
    processor.execute()

if __name__ == "__main__":
    main()