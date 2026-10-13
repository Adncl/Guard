#!/usr/bin/env python3
import sqlite3, json
db = sqlite3.connect('/workspace/output/bind9-analysis/sqlite_BIND9.db')
rows = db.execute('SELECT rule_desc, length(code_snippet), length(call_graph), length(llm_response) FROM rule_code_snippet').fetchall()
for i, r in enumerate(rows, 1):
    rule_short = r[0][:70]
    has_snippet = 'YES' if r[1] and r[1] > 10 else 'NO'
    has_cgraph = 'YES' if r[2] and r[2] > 10 else 'NO'
    has_llm = 'YES' if r[3] and r[3] > 10 else 'NO'
    print(f'{i:2d} | {has_snippet:4s} snippet ({r[1]:6d}B) | {has_cgraph:4s} cgraph | {has_llm:4s} llm | {rule_short}')
