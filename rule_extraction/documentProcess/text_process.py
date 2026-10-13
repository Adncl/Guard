import re
import json
import os


def remove_links(text):
    return re.sub(r'\[([^\]]*)\]\([^\)]*\)', r'\1', text)


def remove_appendix_section(text):
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.strip().startswith(("Appendix", "Reference")):
            return "\n".join(lines[:i])
    return text


def extract_markdown_hierarchy(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        text = f.read()

    result = {}
    heading_stack = []  # [(level, title)]
    content_stack = []
    heading_pattern = re.compile(r'^(#{1,6})\s*(.*)') 

    def save_content():
        if heading_stack and content_stack:
            path = [remove_links(h[1]) for h in heading_stack]
            content = '\n'.join(content_stack).strip()
            if path and content:
                result[" -> ".join(path)] = remove_appendix_section(content)

    for raw_line in text.split('\n'):
        line = raw_line.replace("\xa0", " ").rstrip()
        match = heading_pattern.match(line)
        if match:
            save_content()

            level = len(match.group(1))
            heading_text = match.group(2).strip()

            while heading_stack and heading_stack[-1][0] >= level:
                heading_stack.pop()

            heading_stack.append((level, heading_text))
            content_stack = []
        else:
            content_stack.append(remove_links(line.strip()))

    save_content()
    return result


def filter_headings_content(headings):
    filtered = {}
    started = False
    for heading, content in headings.items():
        if "1." in heading:
            started = True
        if started:
            if any(k in heading for k in ["References", "Appendix"]):
                break
            filtered[heading] = content
    return filtered


def clean_text(text):
    replacements = {
        "\x92": "'", "\xa0": " ", "Â": "", "â\x80\x91": "-",
        "“": "\"", "”": "\"", "\x96": "", "$": ""
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return re.sub(r'\s+', ' ', text).strip()


def process_text(config):
    print("🔄 Processing text content...")
    md_path = config["paths"]["markdown"]

    headings_content = extract_markdown_hierarchy(md_path)
    filtered = filter_headings_content(headings_content)

    cleaned = {clean_text(k): clean_text(v) for k, v in filtered.items()}

    output_path = config["paths"]["text_processed"]
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned, f, ensure_ascii=False, indent=2)

    headings_list = list(cleaned.keys())
    with open(config["paths"]["headings"], 'w', encoding='utf-8') as f:
        json.dump(headings_list, f, ensure_ascii=False, indent=2)

    print(f"✅ Text processing completed\n   Content saved to: {output_path}\n   Heading chain saved to: {config['paths']['headings']}")
    return cleaned