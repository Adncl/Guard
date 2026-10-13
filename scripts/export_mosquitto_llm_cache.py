"""Export the completed Mosquitto LLM observations without altering the DB."""
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / 'output/mosquitto-analysis/sqlite_Mosquitto.db'
OUT = ROOT / 'output/mosquitto-llm-cache-export.json'


def rule_from_prompt(prompt):
    marker = 'Rule: '
    if marker not in prompt:
        return None
    return prompt.split(marker, 1)[1].splitlines()[0]


def main():
    db = sqlite3.connect(DB)
    rows = []
    for stage, model, prompt, response, created_at, served_model in db.execute(
            "SELECT stage,model,prompt,response,created_at,served_model "
            "FROM llm_cache WHERE stage IN ('inconsistency','self-consistency') ORDER BY created_at"):
        item = {
            'stage': stage,
            'model': model,
            'served_model': served_model,
            'created_at': created_at,
            'rule': rule_from_prompt(prompt),
            'response': json.loads(response),
        }
        rows.append(item)
    payload = {
        'scope': 'Completed live DeepSeek detection observations retained in llm_cache; current detection rows may be reset for a clean resume',
        'database': 'output/mosquitto-analysis/sqlite_Mosquitto.db',
        'records': len(rows),
        'rows': rows,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
    print(OUT)


if __name__ == '__main__':
    main()
