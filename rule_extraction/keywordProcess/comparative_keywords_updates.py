import json
import argparse
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
from tqdm import tqdm

def load_config() -> Dict:
    """Load unified configuration"""
    config_path = Path(__file__).parent / "directoryStore/config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Configuration loading failed: {str(e)}")
        raise


def build_prompt(content: str, protocol: str, version: str) -> str:
    """Build dynamic prompt"""
    return f"""
# Description
You are given a description extracted from the  {protocol} {version} specification:
{content}

# Comparitive Keyword
You are given a set of original comparitive keywords:
- is equal to  
- matches  
- is identical to  
- is different from  
- does not match  
- is not equal to  
- is greater than  
- is less than  
- exceeds  
- falls within  
- is between X and Y  
- is out of bounds  
- is dependent on  
- is proportional to  
- is correlated with  
- follows  
- precedes  
- occur before  
- implies  
- is consistent with  
- contradicts  
- is more likely than  
- occurs more frequently than  
- has a higher probability than

#Instruction
Your task is to analyze each sentence in the provided description (#Description) to determine if they are synonymous keywords with the keywords provided in #Comparitive Keyword.

You must follow the analysis process below step by step to analyze each sentence:
1. Some words of each sentence in "#Description" can be directly replaced by "#Comparitive Keyword" without changing the original meaning of the sentence.
2. The words that can be replaced by "#Comparitive Keyword" that are not part of or a subset of "#Comparitive Keyword".

If 1 and 2 hold simultaneously, output them in the following JSON format:
{{
    "#Comparitive Keyword": ["new_keyword in #Description"]
}}

Otherwise, return an empty JSON object:
{{}}

Please omit all explanatory content.
"""


def process_item(item: tuple, apikey: str, config: Dict, protocol: str, version: str) -> tuple:
    """Process single chapter"""
    heading, content = item
    client = OpenAI(
        api_key=apikey,
        base_url=config["api_settings"]["base_url"]
        #timeout=config["api_settings"].get("timeout", 30.0)
    )

    try:
        response = client.chat.completions.create(
            model=config["api_settings"]["model"],
            messages=[
                {"role": "system", "content": "You are a meticulous protocol document analyst"},
                {"role": "user", "content": build_prompt(content,protocol, version)}
            ],
            response_format={"type": "json_object"},
        )

        # Validate response format
        result = json.loads(response.choices[0].message.content)
        if not all(isinstance(v, list) for v in result.values()):
            raise ValueError("Invalid response format")

        return heading, result

    except json.JSONDecodeError:
        return heading, {"error": "Invalid JSON response"}
    except Exception as e:
        return heading, {"error": str(e)}


def main(apikey: str, protocol: str, version: str):
    """Main processing flow"""
    try:
        # Initialize configuration
        config = load_config()
        project_root = Path(__file__).parent

        # Load input data
        input_path = project_root / config["paths"]["paragraph_output"]
        with open(input_path, "r", encoding="utf-8") as f:
            protocol_chapter = json.load(f)

        # Multi-thread processing
        results = {}
        with ThreadPoolExecutor(
                max_workers=config["api_settings"].get("max_workers", 16)
        ) as executor:
            futures = {
                executor.submit(process_item, item, apikey, config, protocol, version): item
                for item in protocol_chapter.items()
            }

            # Progress bar display
            with tqdm(
                    total=len(futures),
                    desc="🔍 Analyzing comparative relationships",
                    unit="section",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            ) as pbar:
                for future in as_completed(futures):
                    heading, result = future.result()
                    results[heading] = result
                    pbar.update(1)
                    pbar.set_postfix(sec=heading[:15])

        # Save results
        output_path = project_root / config["paths"]["comparative_output"]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"\n✅ Comparative relationship analysis completed, results saved to: {output_path}")

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