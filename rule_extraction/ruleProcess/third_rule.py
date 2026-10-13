import argparse
import pandas as pd
import json
import time
from tqdm import tqdm
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_third_rule(api_key, protocol, version):
    # Read Excel file
    df = pd.read_excel("directoryStore/filtered_sentences.xlsx", engine='openpyxl')

    # Only filter sentences that passed the second stage
    df = df[df["Second_Filter_Result"] == "Conforms"]

    # Handle missing Heading column
    if "Heading" not in df.columns:
        df["Heading"] = ""

    # Prepare processing data
    sentences_to_process = df[["Heading", "Sentence"]].values.tolist()

    # Initialize OpenAI client
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")

    def process_sentence(heading, sentence):
        prompt = f"""
        Given a rule description extracted from the {protocol} {version} specification and the subheading in which it is located：
        {heading}
        {sentence}

        Your task is to analyze the message types and their fields involved in this rule description, as well as the corresponding response message types or fields. Follow these steps for the analysis:
        1. Identify the request message type (req_type) mentioned in the rule.
        2. Extract the fields involved in the request message (req_fields).
        3. Determine the response message type (res_type) mentioned in the rule. If no response message is involved, use an empty string.
        4. Extract the fields involved in the response message (res_fields). If no fields are explicitly mentioned or no response message exists, use an empty array.

        5. Present the analysis results in the following JSON format:
        ```json
        {{
            "rule": "{sentence}",
            "req_type": "",
            "req_fields": [],
            "res_type": "",
            "res_fields": []
        }}
        ```
        """

        print(prompt)  # Debug: print the prompt being sent

        for _ in range(3):  # Retry mechanism for failures
            try:
                response = client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": "You are a network protocol standards developer."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={'type': 'json_object'},
                    stream=False
                )

                model_output = response.choices[0].message.content.strip()
                return json.loads(model_output)

            except Exception as e:
                print(f"API Error: {e}, Retrying...")
                time.sleep(2)

        return {  # Default return structure
            "rule": sentence,
            "req_type": "",
            "req_fields": [],
            "res_type": "",
            "res_fields": []
        }

    # Concurrent processing
    results = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(process_sentence, h, s): (h, s)
            for h, s in sentences_to_process
        }

        # Progress bar display
        progress = tqdm(
            as_completed(futures),
            total=len(futures),
            desc=f"Analyzing {protocol} {version}"
        )

        for future in progress:
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Processing failed: {str(e)}")

    # Save results
    with open("directoryStore/processed_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"\n✅ {protocol} {version} protocol analysis completed, results saved to directoryStore/processed_results.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Protocol Field Parser")
    parser.add_argument("--apikey", required=True, help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True, help="Target protocol name (e.g., HTTP/MQTT)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 1.1/5.0)")
    args = parser.parse_args()

    run_third_rule(
        api_key=args.apikey,
        protocol=args.protocol,
        version=args.version
    )