import requests
from openai import OpenAI


def fetch_dissector(config):
    print("🔄 Fetching protocol dissector...")
    protocol = config["protocol"]
    url = f"https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-{protocol}.c"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(config["paths"]["dissector"], "w", encoding="utf-8") as f:
                f.write(response.text)
            print("✅ Dissector code saved")
            process_keywords(config)
        else:
            print(f"❌ Failed to fetch dissector: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Dissector fetch error: {str(e)}")


def process_keywords(config):
    client = OpenAI(api_key=config["api_key"], base_url="https://api.deepseek.com/v1")

    with open(config["paths"]["dissector"], "r", encoding="utf-8") as f:
        code = f.read()

    prompt = f"""
Here is a code snippet for the Wireshark plugin related to {config['protocol'].upper()} {config['version']}:
{code}

# Objective:
Based on the above code snippet, please help me outline the message types in {config['protocol'].upper()} {config['version']}, and the fields contained in each message type. If a field has multiple different subfields, you need to expand all possible subfield names. The message types, fields, and subfields derived from the code should be as comprehensive as possible (especially regarding subfields), covering all message types, fields, and subfields of {config['protocol'].upper()} {config['version']}.

# Output Requirements:
(1) Output the result in the following JSON format, including only message and field information. Do not include format types of fields, such as "string", "uint8", etc.:
{{
"MessageName1": {{
field1, field2: {{sub_field1, sub_field2...}}, ...}},
"MessageName2": {{
field1, field2: {{sub_field1, sub_field2...}}, ...}}
}}
(2) Do not add any prefix or suffix content to the JSON output;
(3) Do not output any other content, such as explanations or supplementary notes.
"""

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system",
                 "content": "You are a network protocol standards developer, focusing on protocol specifications, field definitions, and constraint rules."},
                {"role": "user", "content": prompt},
            ],
            stream=False
        )
        keywords = response.choices[0].message.content
        with open(config["paths"]["keywords"], "w", encoding="utf-8") as f:
            f.write(keywords)
        print("✅ Keywords extracted")
    except Exception as e:
        print(f"❌ Keyword extraction failed: {str(e)}")