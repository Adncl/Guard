#!/usr/bin/env python3
import os
import argparse
import json


def main():
    parser = argparse.ArgumentParser(description="Universal Protocol Document Processor")
    parser.add_argument("--api-key", required=True, help="DeepSeek API key")
    parser.add_argument("--protocol", required=True, help="Protocol name (e.g. mqtt)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g. 5.0)")
    parser.add_argument("--html-file", required=True, help="Path to protocol HTML document")
    parser.add_argument("--filter-headings", action="store_true", default=True, help="filter the directory (default: enabled)")

    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    store_dir = os.path.join(base_dir, "directoryStore")
    os.makedirs(store_dir, exist_ok=True)

    config = {
        "api_key": args.api_key,
        "protocol": args.protocol.lower(),
        "version": args.version,
        "paths": {
            "directoryStore": os.path.abspath(store_dir),
            "html_input": os.path.join(store_dir,args.html_file),
            "cleaned_html": os.path.join(store_dir, f"{args.protocol}_cleaned.html"),
            "markdown": os.path.join(store_dir, f"final_{args.protocol}.md"),
            "keywords": os.path.join(store_dir, "specify_keywords.txt"),
            "headings": os.path.join(store_dir, "headings.json"),
            "output_json": os.path.join(store_dir, "filtered_headings.json"),
            "output_excel": os.path.join(store_dir, "sentences_analysis.xlsx"),
            "text_processed": os.path.join(store_dir, "text_processed.json"),
            "dissector": os.path.join(store_dir, f"packet-{args.protocol}.c"),
            "tables": os.path.join(store_dir, "tables.json")
        }
    }

    with open(os.path.join(store_dir, "config.json"), "w") as f:
        json.dump(config, f, indent=2)

    from html_process import process_html
    from text_process import process_text
    from specify_keywords import fetch_dissector
    from index_filtering import filter_headings
    from separate_sentences import process_sentences

    process_html(config)
    process_text(config)
    fetch_dissector(config)
    if args.filter_headings:
        filter_headings(config)
    process_sentences(config)


if __name__ == "__main__":
    main()