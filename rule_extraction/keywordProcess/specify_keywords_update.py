import re
import json
import argparse
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
from tqdm import tqdm


def load_config() -> Dict:
    """Load configuration file"""
    config_path = Path(__file__).parent / "directoryStore/config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Configuration loading failed: {str(e)}")
        raise


def process_item(item: tuple, apikey: str, config: Dict, protocol: str, version: str) -> tuple:
    """Thread-safe function for processing individual chapters"""
    heading, content = item
    client = OpenAI(
        api_key=apikey,
        base_url=config["api_settings"]["base_url"]
    )

    try:
        prompt = f"""
You are given a description extracted from the {protocol} {version} specification:
\"\"\"
{content}
\"\"\"

Your task is to analyze this description and check for any synonyms, aliases, abbreviations, or variant expressions of the following {protocol} {version} protocol-related target keywords:
{config["compact_keywords"]}

If you identify any synonyms, aliases, abbreviations, or variant expressions of these keywords in the description, output them in the following JSON format:
{{
    "original_keyword": ["new_keyword1"]
}}

If no synonyms, aliases, abbreviations, or variants are found, return an empty JSON object:
{{}}

Please omit all explanatory content.
        """

        response = client.chat.completions.create(
            model=config["api_settings"]["model"],
            messages=[
                {"role": "system", "content": "You are a network protocol standards developer."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
        )

        result = json.loads(response.choices[0].message.content)
        print(result)
        if not isinstance(result, dict):
            raise ValueError("Invalid response format")

        return heading, result

    except json.JSONDecodeError:
        return heading, {"error": "Invalid JSON response"}
    except Exception as e:
        return heading, {"error": str(e)}


def main(apikey: str, protocol: str, version: str):
    """Main processing flow"""
    try:
        config = load_config()
        project_root = Path(__file__).parent
        project_root1 = Path(__file__).parent.parent

        input_path = project_root / config["paths"]["paragraph_output"]
        with open(input_path, "r", encoding="utf-8") as f:
            protocol_chapter = json.load(f)

        keywords_path = project_root1 / config["paths"]["keyword_list"]
        with open(keywords_path, "r", encoding="utf-8") as f:
            keyword_list = json.load(f)

        config["compact_keywords"] = "[" + ", ".join(f'"{w}"' for w in keyword_list) + "]"

        results = {}
        with ThreadPoolExecutor(
                max_workers=config["api_settings"].get("max_workers", 16)
        ) as executor:
            futures = {
                executor.submit(process_item, item, apikey, config, protocol, version): item
                for item in protocol_chapter.items()
            }

            with tqdm(
                    total=len(futures),
                    desc="🔍 Analyzing protocol document",
                    unit="section",
                    dynamic_ncols=True
            ) as pbar:
                for future in as_completed(futures):
                    heading, result = future.result()
                    results[heading] = result
                    pbar.update(1)
                    pbar.set_postfix_str(f"Current section: {heading[:15]}...")

        output_path = project_root / config["paths"]["specify_output"]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"\n✅ Specification keyword expansion completed, results saved to: {output_path}")

    except Exception as e:
        print(f"❌ Processing failed: {str(e)}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    main(args.apikey, args.protocol, args.version)