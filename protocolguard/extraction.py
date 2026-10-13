"""Hybrid normative-rule extraction with section context and dissector keywords."""
import argparse
import json
from pathlib import Path
import re
from .common import LLM, connect, database_path, load_config, read_rules

MODAL = re.compile(r'\b(?:MUST(?: NOT)?|SHALL(?: NOT)?|REQUIRED|SHOULD(?: NOT)?|RECOMMENDED)\b')
COMPARATIVE = re.compile(r'\b(?:greater than|less than|at least|at most|equal to|between|exceed)\b', re.I)


def extract(config, html_path, output, match=None, offline=False):
    from lxml import html
    doc = html.parse(str(html_path))
    for node in doc.xpath('//script|//style|//nav'):
        node.drop_tree()
    paragraphs = [' '.join(n.text_content().split()) for n in doc.xpath('//p|//li')]
    paragraphs = [p for p in paragraphs if p]
    db = connect(database_path(config))
    llm = None if offline else LLM(config, db)
    # Protocol-specific Wireshark dissector string tables feed keyword
    # extraction; fall back to the MQTT table only if the protocol has none.
    store = Path(__file__).resolve().parents[1] / 'rule_extraction/documentProcess/directoryStore'
    dissector = store / f"packet-{config['project']['protocol_name'].lower()}.c"
    if not dissector.exists():
        dissector = store / 'packet-mqtt.c'
    terms = sorted(set(re.findall(r'"([A-Za-z][A-Za-z ]{2,45})"', dissector.read_text(errors='replace')))) if dissector.exists() else []
    if llm:
        keywords = llm.query('protocol-keywords', f'''Extract protocol-specific message and field names from this Wireshark
dissector string table. Return {{"keywords":["message or field name"]}}.
Protocol: {config['project']['protocol_name']} {config['project']['protocol_version']}
{json.dumps(terms)}''').get('keywords', [])
    else:
        keywords = terms
    keywords += ['packet', 'client', 'server', 'connection']
    if not all(isinstance(k, str) for k in keywords):
        raise ValueError('Model keywords must be strings')
    candidates = []
    seen = set()
    for i, paragraph in enumerate(paragraphs):
        if match and not re.search(match, paragraph):
            continue
        for sentence in re.split(r'(?<=[.!?])\s+(?=[A-Z])', paragraph):
            if not (MODAL.search(sentence) or COMPARATIVE.search(sentence)):
                continue
            if not any(k.lower() in sentence.lower() for k in keywords if k):
                continue
            if sentence in seen:
                continue
            seen.add(sentence)
            candidates.append({'sentence': sentence, 'context': '\n'.join(paragraphs[max(0,i-2):i+3])})
    if not candidates:
        raise ValueError('No normative candidates matched the selected document/rule IDs')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix('.candidates.json').write_text(json.dumps(candidates, indent=2, ensure_ascii=False), encoding='utf-8')
    if offline:
        print(f'Saved {len(candidates)} heuristic candidates; no semantic rules generated without an LLM')
        return
    rules = []
    for candidate in candidates:
        value = llm.query('rule-contextualization', f'''Contextualize the normative candidate using surrounding specification text:
resolve references and merge logically necessary clauses. Preserve mandatory vs optional behavior and exact requirements.
Then structure into JSON: {{"rules":[{{"rule":"self-contained normative rule, including its identifier",
"req_type":"request packet type", "req_fields":["field and parent field"],
"res_type":"response packet type or empty", "res_fields":[]}}]}}.
Do not invent requirements or include unrelated rules. Protocol: {config['project']['protocol_name']} {config['project']['protocol_version']}.
Candidate data: {json.dumps(candidate, ensure_ascii=False)}''')
        rules.extend(r for r in value.get('rules', []) if not match or re.search(match, r.get('rule', '')))
    unique = {}
    for rule in rules:
        identifier = re.search(r'MQTT-\d+(?:\.\d+)*-\d+', rule['rule'])
        key = identifier.group(0) if identifier else rule['rule']
        unique.setdefault(key, rule)
    rules = list(unique.values())
    output.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding='utf-8')
    read_rules(output)
    print(f'Extracted {len(rules)} structured rules to {output}')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--html', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--match', help='Regex selecting paragraphs by rule identifier; omit for the whole document')
    p.add_argument('--offline', action='store_true')
    a = p.parse_args()
    extract(load_config(a.config), a.html, a.output, a.match, a.offline)
