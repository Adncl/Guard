import json
import argparse
from pathlib import Path
from typing import Set, List, Dict
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


def load_filter_words(config: Dict, filter_type: str) -> Set[str]:
    """Load filter word set"""
    return set(config["filters"].get(filter_type, []))

def load_processed_data(config: Dict, data_type: str) -> Dict:
    """Load intermediate result data"""
    data_path = Path(__file__).parent / config["paths"][f"{data_type}_output"]
    try:
        with open(data_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ {data_type} data loading failed: {str(e)}")
        raise

def extract_keywords(data: Dict, filter_words: Set[str] = None) -> List[str]:
    """Extract and filter keywords from processing results"""
    if filter_words is None:
        filter_words = set()

    keywords = []

    for section, content in data.items():
        try:
            if not content or content == "{}":
                continue

            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except json.JSONDecodeError:
                    continue

            if isinstance(content, dict):
                for key, values in content.items():
                    if isinstance(values, list):
                        keywords.extend([v for v in values if v not in filter_words])
                    elif isinstance(values, dict):
                        keywords.extend([k for k in values.keys() if k not in filter_words])
                        for v in values.values():
                            if isinstance(v, list):
                                keywords.extend([item for item in v if item not in filter_words])
                            elif isinstance(v, str) and v not in filter_words:
                                keywords.append(v)

        except Exception as e:
            print(f"⚠️ Section processing exception [{section[:15]}]: {str(e)}")

    return list(set(keywords))


def filter_specify_keywords(client: OpenAI, keywords: List[str], protocol: str, version: str, model: str) -> List[str]:
    """Use LLM to filter specify keywords - keep only message types and composition format related keywords"""
    if not keywords:
        return []
    
    prompt = f"""You are given a list of keywords extracted from the {protocol} {version} specification.

Your task is to filter this list and ONLY keep keywords that are directly related to:
1. Message types
2. Message composition formats (e.g., packet structure, field names, header components, etc.)
3. Protocol-specific data structures and formats

REMOVE keywords that are:
- General networking terms not specific to {protocol} message types or formats
- Implementation details unrelated to message structure
- General programming concepts
- Non-technical terms

Input keywords:
{json.dumps(keywords, ensure_ascii=False, indent=2)}

Please return ONLY a JSON object with a single key "filtered_keywords" containing an array of the keywords that should be kept.

Example format:
{{
  "filtered_keywords": ["CONNECT", "PUBLISH", "Fixed Header", "Variable Header", "Payload"]
}}

Do not include any explanations, only return the JSON object."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            timeout=60
        )
        
        result = json.loads(response.choices[0].message.content)
        filtered = result.get("filtered_keywords", [])
        print(f"  Specify keywords: {len(keywords)} → {len(filtered)} (filtered {len(keywords) - len(filtered)})")
        return filtered
    except Exception as e:
        print(f"❌ Error filtering specify keywords: {str(e)}")
        return keywords


def filter_modal_keywords(client: OpenAI, keywords: List[str], model: str) -> List[str]:
    """Use LLM to filter modal keywords - keep only mandatory and strongly recommended modality keywords"""
    if not keywords:
        return []
    
    prompt = f"""You are given a list of modal keywords extracted from a protocol specification.

Your task is to filter this list and ONLY keep keywords that express:
1. Mandatory requirements (e.g., MUST, REQUIRED, SHALL)
2. Strong recommendations (e.g., SHOULD, RECOMMENDED)

REMOVE keywords that express:
- Weak recommendations or suggestions (e.g., MAY, OPTIONAL, MIGHT)
- Prohibitions without strong enforcement (e.g., SHOULD NOT in non-critical contexts)
- General or neutral modality terms

Input keywords:
{json.dumps(keywords, ensure_ascii=False, indent=2)}

Please return ONLY a JSON object with a single key "filtered_keywords" containing an array of the keywords that should be kept.

Example format:
{{
  "filtered_keywords": ["MUST", "SHALL", "REQUIRED", "SHOULD", "RECOMMENDED"]
}}

Do not include any explanations, only return the JSON object."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            timeout=60
        )
        
        result = json.loads(response.choices[0].message.content)
        filtered = result.get("filtered_keywords", [])
        print(f"  Modal keywords: {len(keywords)} → {len(filtered)} (filtered {len(keywords) - len(filtered)})")
        return filtered
    except Exception as e:
        print(f"❌ Error filtering modal keywords: {str(e)}")
        return keywords


def filter_comparative_keywords(client: OpenAI, keywords: List[str], model: str) -> List[str]:
    """Use LLM to filter comparative keywords - keep only numerical comparison keywords"""
    if not keywords:
        return []
    
    prompt = f"""You are given a list of comparative keywords extracted from a protocol specification.

Your task is to filter this list and ONLY keep keywords that express:
1. Numerical comparisons (e.g., greater than, less than, equal to, maximum, minimum)
2. Quantitative relationships (e.g., exceeds, below, at least, no more than)
3. Size/length/value comparisons

REMOVE keywords that express:
- Non-numerical comparisons (e.g., similar to, different from)
- General comparison terms without numerical context
- Logical operators not related to numerical comparison
- Temporal comparisons (e.g., before, after) unless related to numerical values

Input keywords:
{json.dumps(keywords, ensure_ascii=False, indent=2)}

Please return ONLY a JSON object with a single key "filtered_keywords" containing an array of the keywords that should be kept.

Example format:
{{
  "filtered_keywords": ["greater than", "less than", "equal to", "maximum", "minimum", "exceeds"]
}}

Do not include any explanations, only return the JSON object."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            timeout=60
        )
        
        result = json.loads(response.choices[0].message.content)
        filtered = result.get("filtered_keywords", [])
        print(f"  Comparative keywords: {len(keywords)} → {len(filtered)} (filtered {len(keywords) - len(filtered)})")
        return filtered
    except Exception as e:
        print(f"❌ Error filtering comparative keywords: {str(e)}")
        return keywords


def main(apikey: str, protocol: str, version: str):
    """Main processing flow"""
    try:
        config = load_config()
        project_root = Path(__file__).parent

        # Initialize OpenAI client
        client = OpenAI(
            api_key=apikey,
            base_url=config["api_settings"]["base_url"]
        )
        model = config["api_settings"]["model"]

        # Load filters
        field_filter = load_filter_words(config, "specify")
        comp_filter = load_filter_words(config, "comparative")

        # Extract initial keywords
        print("\n📝 Extracting keywords from processed data...")
        initial_results = {
            "specify": extract_keywords(
                load_processed_data(config, "specify"),
                field_filter
            ),
            "modal": extract_keywords(
                load_processed_data(config, "modal")
            ),
            "comparative": extract_keywords(
                load_processed_data(config, "comparative"),
                comp_filter
            )
        }

        print(f"\nInitial keyword counts:")
        print(f"  Specify: {len(initial_results['specify'])} items")
        print(f"  Modal: {len(initial_results['modal'])} items")
        print(f"  Comparative: {len(initial_results['comparative'])} items")

        # Apply LLM filtering
        print(f"\nApplying LLM filtering for {protocol} {version}...")
        
        filtered_results = {
            "specify": filter_specify_keywords(
                client, 
                initial_results["specify"], 
                protocol, 
                version,
                model
            ),
            "modal": filter_modal_keywords(
                client, 
                initial_results["modal"],
                model
            ),
            "comparative": filter_comparative_keywords(
                client, 
                initial_results["comparative"],
                model
            )
        }

        # Save results
        output_path = project_root / config["paths"]["final_output"]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(filtered_results, f, ensure_ascii=False, indent=2)

        print("\nKeyword merging and filtering completed")
        print(f"\nFinal keyword counts:")
        print(f"  Specify: {len(filtered_results['specify'])} items")
        print(f"  Modal: {len(filtered_results['modal'])} items")
        print(f"  Comparative: {len(filtered_results['comparative'])} items")
        print(f"\nResult file: {output_path}")

    except Exception as e:
        print(f"Final result generation failed: {str(e)}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True, help="Target protocol name (e.g., MQTT)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 5.0)")
    args = parser.parse_args()
    main(args.apikey, args.protocol, args.version)
