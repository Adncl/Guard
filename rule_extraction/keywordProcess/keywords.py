import json
import re
from pathlib import Path
from typing import Dict, List


def extract_quoted_keywords(config: Dict) -> List[str]:
    try:
        project_root = Path(__file__).parent.parent
        json_path = project_root / config["paths"]["keywords_json"]

        if not json_path.exists():
            raise FileNotFoundError(f"The JSON keyword file does not exist: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            content = re.sub(r',\s*}(?=,|\s*$)', '}', content)  
            content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
            data = json.loads(content)

        keywords = []

        def _extract(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    keywords.append(f'"{k}"')
                    _extract(v)
            elif isinstance(obj, list):
                for item in obj:
                    _extract(item)
            elif isinstance(obj, str):
                keywords.append(f'"{obj}"')

        _extract(data)
        return list(set(keywords)) 

    except Exception as e:
        print(f"❌ JSON keyword extraction failed: {str(e)}")
        return []


def extract_txt_keywords(config: Dict) -> List[str]:
    try:
        project_root = Path(__file__).parent.parent
        txt_path = project_root / config["paths"]["specify_keywords"]

        if not txt_path.exists():
            raise FileNotFoundError(f"The text keyword file does not exist: {txt_path}")

        with open(txt_path, "r", encoding="utf-8") as f:
            content = f.read()
            return [f'"{m}"' for m in re.findall(r'"([^"]*)"', content, re.DOTALL)]  

    except Exception as e:
        print(f"❌ Failed to extract text keywords: {str(e)}")
        return []


def reconstruct_paragraphs(config: Dict) -> None:
    try:

        project_root1 = Path(__file__).parent.parent
        project_root2 = Path(__file__).parent
        input_path = project_root1 / config["paths"]["input_json"]
        output_path = project_root2 / config["paths"]["paragraph_output"]


        with open(input_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        results = {}
        for heading, data in content.items():
            try:
                if isinstance(data, str):
                    data = json.loads(data.replace('\n', ''))

                sentences = data.get(heading, data) if isinstance(data, dict) else data

                paragraph = ' '.join(
                    item["Original Sentence"] if item.get("Adjusted Sentence") == "No adjustment needed" else item.get("Adjusted Sentence",item.get("Original Sentence", str(item)))
                    for item in sentences
                )
                results[heading] = re.sub(r'\s+', ' ', paragraph).strip()

            except Exception as e:
                print(f"⚠️ Chapter processing failed: {heading} - {str(e)}")
                results[heading] = ""

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"✅ A paragraph file has been generated: {output_path}")

    except Exception as e:
        print(f"❌ Failed to reorganize paragraphs: {str(e)}")
        raise


def main():
    """Main processing flow"""
    try:
        print("=== Starting configuration loading ===")
        project_root = Path(__file__).parent.parent
        config_path = project_root / "keywordProcess/directoryStore/config.json"

        # Load configuration
        print("=== Loading configuration file ===")
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
            assert "paths" in config, "Configuration missing 'paths' field"
            assert "processing" in config, "Configuration missing 'processing' field"

        # Merge keywords from multiple sources
        combined_keywords = []

        # JSON source processing
        if "json" in config["processing"]["keyword_sources"]:
            print(">>> Processing JSON source") 
            json_keywords = extract_quoted_keywords(config)
            combined_keywords.extend(json_keywords)
            print(f"Extracted {len(json_keywords)} keywords from JSON")

        # Text source processing
        if "txt" in config["processing"]["keyword_sources"]:
            print(">>> Processing text source")
            txt_keywords = extract_txt_keywords(config)
            combined_keywords.extend(txt_keywords)
            print(f"Extracted {len(txt_keywords)} keywords from text")

        # Save keywords
        if combined_keywords:
            output_path = project_root / config["paths"]["keyword_list"]
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(list(combined_keywords), f, indent=2)
            print(f"✅ Merged keyword count: {len(combined_keywords)}")

        # Save paragraphs
        reconstruct_paragraphs(config)

    except FileNotFoundError as e:
        print(f"File not found: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {str(e)}")
    except Exception as e:
        print(f"Uncaught error: {str(e)}")


if __name__ == "__main__":
    main()

MODAL_KEYWORDS = {
    "Mandatory requirements": ["MUST", "SHALL", "REQUIRED"],
    "Prohibitive requirements": ["MUST NOT", "SHALL NOT", "PROHIBITED"],
    "Recommendatory suggestions": ["SHOULD", "RECOMMENDED"],
    "Non-recommendatory suggestions": ["SHOULD NOT", "NOT RECOMMENDED"],
    "Permissive clauses": ["MAY", "OPTIONAL"]
}