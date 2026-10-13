#!/usr/bin/env python3
import sqlite3, json
db = sqlite3.connect('/workspace/output/bind9-analysis/sqlite_BIND9.db')
rows = db.execute('SELECT rule_desc, llm_response FROM rule_code_snippet').fetchall()
print(f'{"#":>2} | {"Result":<20} | Rule')
print('-' * 100)
violation_count = 0
no_violation_count = 0
inconclusive_count = 0
for i, (rule, resp_raw) in enumerate(rows, 1):
    if resp_raw:
        try:
            resp = json.loads(resp_raw)
            result = resp.get('result', 'unknown')
        except:
            result = 'parse_error'
    else:
        result = 'empty'
    if result == 'violation found!':
        violation_count += 1
    elif result == 'no violation found!':
        no_violation_count += 1
    else:
        inconclusive_count += 1
    print(f'{i:2d} | {result:<20} | {rule[:75]}')
print('-' * 100)
print(f'Summary: {violation_count} violations, {no_violation_count} no violation, {inconclusive_count} inconclusive')
