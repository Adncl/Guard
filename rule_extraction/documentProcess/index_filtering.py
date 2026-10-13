import re
import json
from openai import OpenAI
from collections import defaultdict
import os


def filter_headings(config):
    print("🔄 Filtering protocol headings...")
    with open(config["paths"]["text_processed"], "r") as f:
        headings = json.load(f)

    grouped = defaultdict(list)
    pattern = re.compile(r"^(\d+)[\.\s]")
    for heading in headings:
        match = pattern.match(heading)
        if match:
            grouped[match.group(1)].append(heading)

    headings_str = "\n".join(h for sub in grouped.values() for h in sub)
    with open(config["paths"]["keywords"], "r") as f:
        keywords = f.read()

    prompt = f"""
Given the following table of contents for the {config['protocol']} {config['version']} protocol documentation, please predict which sections may contain descriptions of {config['protocol']} {config['version']} message packets and their respective fields. Please filter according to the following criteria:

1. **Message Types and Control**: If an entry includes specific message packet names for {config['protocol']} {config['version']}, then this entry is required and should be selected. Specific message packet names for {config['protocol']} {config['version']} can refer to the specific information provided below.
2. **Field Information**: If an entry includes the names of specific fields within {config['protocol']} {config['version']} message packets, then this entry is required and should be selected. Specific field information within {config['protocol']} {config['version']} message packets can refer to the specific information provided below.
3. **Protocol Behavior Affecting Fields**: If it is predicted that the content under an entry describes protocol behaviors such as session management, message flow, QoS mechanisms, subscription management, flow control, error handling, etc., and these behaviors may affect the fields of {config['protocol']} {config['version']} messages, then this entry is also required and should be selected.

The following are the specific message types and fields within messages for {config['protocol']} {config['version']}:
{keywords}

Here is the chapter table of contents to be filtered:
{headings_str}

Output Format:
Please output a Python list as the final result, where each element in the list is an entry deemed necessary after filtering. Do not output any additional content, such as analysis processes or explanatory information. The output format should be as follows:
["Entry 1", "Entry 2", ...]

Note:
(1) If a major chapter contains entries that meet the criteria, exercise caution when filtering parallel sections of these entries. Unless an entry is clearly irrelevant, if it has even a slight relation to the requirements, it should be included.
(2) If an entry meets the criteria, its sub-entries should also be included in the list.
"""

    client = OpenAI(api_key=config["api_key"], base_url="https://api.deepseek.com/v1")
    try:
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        selected = eval(response.choices[0].message.content)
        with open(config["paths"]["headings"], "w") as f:
            json.dump(selected, f)
        print(f"✅ Selected {len(selected)} headings")
    except Exception as e:
        print(f"❌ Heading selection failed: {str(e)}")