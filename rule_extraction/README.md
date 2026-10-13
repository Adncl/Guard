# Rule Extraction

This module extracts protocol rules from specification documents through a three-step process.

## Usage

### Step 1: Document Processing

Preprocess the protocol document, including packet format keyword extraction and sentence segmentation.

```bash
cd /root/projects/protocolguard_artefact/rule_extraction/documentProcess/
python3 __main__.py --api-key $DEEPSEEK_API_KEY --protocol mqtt --version 5.0 --html-file /root/projects/protocolguard_artefact/rule_extraction/documentProcess/directoryStore/mqtt.html
```

**Parameters:**
- `--api-key`: Your DeepSeek API key
- `--protocol`: Target protocol name (e.g., mqtt, http)
- `--version`: Protocol version (e.g., 5.0)
- `--html-file`: Path to the protocol specification HTML file

### Step 2: Keyword Extraction and Update

Extract and update keywords from the processed document.

```bash
cd /root/projects/protocolguard_artefact/rule_extraction/keywordProcess/
python3 __main__.py --apikey $DEEPSEEK_API_KEY --protocol MQTT --version 5.0
```

**Parameters:**
- `--apikey`: Your DeepSeek API key
- `--protocol`: Target protocol name 
- `--version`: Protocol version

### Step 3: Rule Processing

Process and extract protocol rules from the analyzed content.

```bash
cd /root/projects/protocolguard_artefact/rule_extraction/ruleProcess
python3 __main__.py --apikey $DEEPSEEK_API_KEY --protocol MQTT --version 5.0
```

**Parameters:**
- `--apikey`: Your DeepSeek API key
- `--protocol`: Target protocol name
- `--version`: Protocol version

## Output

The pipeline generates several output files in the respective `directoryStore/` folders:

- **Step 1**: Processed document with filtered headings and separated sentences
- **Step 2**: Extracted keywords (specify, modal, comparative)
- **Step 3**: Final protocol rules in JSON format