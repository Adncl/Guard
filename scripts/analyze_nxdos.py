#!/usr/bin/env python3
import json
from collections import Counter

queries = []
for l in open("/workspace/output/cname-nxdos-test/auth.jsonl"):
    if l.strip():
        queries.append(json.loads(l))

print(f"Total upstream queries: {len(queries)}")
print()

name_counts = Counter(q["q"] for q in queries)
print("Query name distribution (top 15):")
for name, count in name_counts.most_common(15):
    print(f"  {name:<40} {count}")

print()
result_counts = Counter(q["r"] for q in queries)
print("Result distribution:")
for r, count in result_counts.most_common():
    print(f"  {r:<30} {count}")

# Analyze first query vs later queries
ts_list = sorted(q["ts"] for q in queries)
if ts_list:
    print(f"\nTime range: {ts_list[0]:.2f} - {ts_list[-1]:.2f}s ({ts_list[-1]-ts_list[0]:.2f}s total)")
    
# Find queries specifically about victim.com / deadzone
victim_q = [q for q in queries if 'victi' in q['q'].lower() or 'deadzone' in q['q'].lower() or 'nonexist' in q['q'].lower()]
print(f"\nVictim/deadzone-related queries: {len(victim_q)}")
for q in victim_q[:20]:
    print(f"  {q['q']:<40} {q['t']:<8} → {q['r']}")

# Check: queries about ns.victim.com CNAME
cname_q = [q for q in queries if q['r'] == 'CNAME→NX']
print(f"\nCNAME→NX queries: {len(cname_q)}")
for q in cname_q[:10]:
    print(f"  {q['q']:<40} {q['t']:<8}")

# Check: queries about deadzone.xyz
deadzone_q = [q for q in queries if 'deadzone' in q['q'].lower() or q['r'] == 'NXDOMAIN_deadzone']
print(f"\nDeadzone NXDOMAIN queries: {len(deadzone_q)}")
for q in deadzone_q[:10]:
    print(f"  {q['q']:<40} {q['t']:<8} → {q['r']}")
