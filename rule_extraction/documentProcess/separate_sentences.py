import re
import json
import pandas as pd
from tenacity import retry, stop_after_attempt, wait_random_exponential
from openai import OpenAI
import concurrent.futures
import traceback  # 添加 traceback 模块

from tqdm import tqdm


@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=10))
def process_sentence(client, heading, sentence):
    prompt = f"""You are a precise language analysis assistant. I will provide a series of sentences (divided by chapters). Please analyze the completeness of each sentence and correct any potential issues with ambiguous pronoun references. Follow these rules:

    1. **Check completeness sentence by sentence**:
    - Directly analyze whether each sentence is complete.
    - If a sentence contains pronouns (such as "it", "they", "this", "that", etc.), check whether their referents are clear.

    2. **Handling pronouns**:
    - **If the referent of the pronoun is clear**, no modification is needed.
    - **If the referent of the pronoun is unclear**, use the provided context (the set of sentences in the current chapter) to find appropriate information, replace the pronoun with a clear referent, and adjust the sentence structure.

    3. **Analyze whether the sentence contains irrelevant characters (such as TABLE/FIGURE descriptions or garbled text) and delete them**.

    4. **If the sentence contains non-natural language characters, rephrase it in natural language**.

    5. **Format requirements**:
    - **Strictly output in JSON format**, without any additional text, explanations, or comments. Only return structured JSON data.
    - The JSON structure is as follows:
    ```json
        {{
            "Chapter Title": [
                {{"Original Sentence": "Original sentence 1", "Adjusted Sentence": "Adjusted complete sentence"}},
                {{"Original Sentence": "Original sentence 2", "Adjusted Sentence": "No adjustment needed"}}
            ]
        }}
    ```

    💡 **Strictly adhere to the JSON format for output. Do not add any extra text!**
    Here is the content for you to process:
    【Chapter Title】: "{heading}"

    【List of Divided Sentences】: {sentence}

    ⚠️ Special Notes:
    - Do not add any extra text outside the JSON.
    - Ensure all strings use double quotes.
    - Ensure every key has a corresponding value"""

    # print("prompt:", prompt)  # Debug: print the prompt being sent

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system",
             "content": "You are an expert in network protocol analysis. Ensure each sentence is self-contained by resolving unclear pronoun references using context."},
            {"role": "user", "content": prompt},
        ],
        response_format={
            'type': 'json_object'
        }
    )
    return response.choices[0].message.content.strip()


def process_sentences(config):
    print("🔄 Processing sentences...")

    with open(config["paths"]["text_processed"], "r") as f:
        headings = json.load(f)
    with open(config["paths"]["headings"], "r") as f:
        selected = json.load(f)

    client = OpenAI(api_key=config["api_key"], base_url="https://api.deepseek.com/v1")
    results = {}
    df_data = []

    with tqdm(total=len(selected), desc="handling section") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:  
            futures = {}

            for heading in selected:
                if heading in headings:
                    sentences = [s for s in re.split(r'(?<=[.!?])\s+', headings[heading]) if s.strip()]
                    futures[executor.submit(process_sentence, client, heading, sentences)] = heading

            for future in concurrent.futures.as_completed(futures):
                heading = futures[future]
                try:
                    optimized_text = future.result()
                    results[heading] = optimized_text

                    original_sentences = re.split(r'(?<=[.!?])\s+', headings[heading])
                    optimized_sentences = re.split(r'(?<=[.!?])\s+', optimized_text)
                    for orig, opt in zip(original_sentences, optimized_sentences):
                        df_data.append([heading, orig, opt])

                except Exception as e:
                    print(f"❌ Chapter processing failed: {heading} - {str(e)}")
                    print(traceback.format_exc())  # 打印完整的异常堆栈信息
                    results[heading] = headings[heading]  
                finally:
                    pbar.update(1)

    pd.DataFrame(df_data, columns=["Chapter", "Original Sentence", "Correction"]).to_excel(
        config["paths"]["output_excel"], index=False)

    with open(config["paths"]["output_json"], "w", encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)