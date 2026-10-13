import json
import argparse
from pathlib import Path
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI
from tqdm import tqdm
from keywords import MODAL_KEYWORDS


def load_config() -> Dict:
    """Load unified configuration"""
    config_path = Path(__file__).parent / "directoryStore/config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Configuration loading failed: {str(e)}")
        raise


def process_item(item: tuple, apikey: str, config: Dict) -> tuple:
    """Thread-safe function for processing individual chapters"""
    heading, content = item
    client = OpenAI(
        api_key=apikey,
        base_url=config["api_settings"]["base_url"]
    )

    try:
        prompt_template = f"""
You are a professional network protocol analysis expert, skilled in parsing protocol documents and extracting different expressions of **modal keywords** in protocols. Your task is to analyze protocol documents and identify different expressions for given **modal keywords**, including alternative expressions in technical standards.

[Task Objective]
Identify all synonymous expressions in the protocol document that express the following 4 levels of constraint:
1. **Mandatory requirements** (RFC 2119 MUST level)
2. **Prohibitive requirements** (RFC 2119 MUST NOT level)  
3. **Recommendatory suggestions** (RFC 2119 SHOULD level) and Non-recommendatory suggestions
4. **Permissive clauses** (RFC 2119 MAY level)  

[Input]  
1. **Protocol document fragment**:
   \"\"\"  
   {content}  
   \"\"\"
2. **Target modal keywords**:  
   {MODAL_KEYWORDS}  

[Extraction Rules]
1. **Semantic strength matching principle**:
   - Mandatory: Includes obligatory verbs or absolute negation
   - Recommendatory: Includes suggestive verbs
   - Permissive: Includes selective adverbs

2. **Syntactic feature validation**:
   - Accept passive voice: `is required to` ≡ `must`
   - Accept modal verb variations: `cannot` ≡ `must not`
   - Reject non-binding expressions: `possible to` (unless explicitly modifying constraint words)
   
3. **Protocol-specific expression handling** (also content to be extracted):
   - Legal terms: e.g., `shall be deemed to`
   - Technical prohibitions: e.g., `is a error`
   - Conditional constraints: e.g., `when X, Y shall`
   
[Output Rules]  
1. **Contextual accuracy**: Ensure extracted terms match the semantics of original keywords in actual protocol document usage.  
2. **Original text consistency**: Must extract according to original text format, do not change the form of original content.  
3. **Standard format**: Return in JSON list format, ensuring data is clear and readable.

[Output Format]  
1. Please return results in **JSON format**. For example:
{{
    "# Modality Keyword": ["new_keyword in #Description"]
}}

If no synonymous expressions are found, return {{}}.
{{}}

Do not return any extra content, such as explanatory text.
        """

        response = client.chat.completions.create(
            model=config["api_settings"]["model"],
            messages=[
                {"role": "system", "content": "You are a meticulous network protocol analyst"},
                {"role": "user", "content": prompt_template}
            ],
            response_format={"type": "json_object"},
        )

        result = json.loads(response.choices[0].message.content)
        if not all(isinstance(v, list) for v in result.values()):
            raise ValueError("Invalid response format")

        return heading, result

    except json.JSONDecodeError:
        return heading, {"error": "Invalid JSON response"}
    except Exception as e:
        return heading, {"error": str(e)}


def main(apikey: str):
    """Main processing flow"""
    try:
        config = load_config()
        project_root = Path(__file__).parent
        
        input_path = project_root / config["paths"]["paragraph_output"]
        with open(input_path, "r", encoding="utf-8") as f:
            protocol_chapter = json.load(f)

        results = {}
        with ThreadPoolExecutor(
                max_workers=config["api_settings"].get("max_workers", 16)
        ) as executor:
            futures = {
                executor.submit(process_item, item, apikey, config): item
                for item in protocol_chapter.items()
            }

            with tqdm(
                    total=len(futures),
                    desc="🔍 Analyzing modal keywords",
                    unit="section",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            ) as pbar:
                for future in as_completed(futures):
                    heading, result = future.result()
                    results[heading] = result
                    pbar.update(1)
                    pbar.set_postfix(sec=heading[:15])

        output_path = project_root / config["paths"]["modal_output"]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"\n✅ Modal keyword expansion completed, results saved to: {output_path}")

    except Exception as e:
        print(f"❌ Processing failed: {str(e)}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    args = parser.parse_args()

    main(args.apikey)