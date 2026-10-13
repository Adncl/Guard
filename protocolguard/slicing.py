"""LLM-guided slicing over LLVM def-use and memory-dependence edges.

The missing author's implementation is reconstructed, not recovered byte for
byte. The LLVM plugins retain the released command-line interface.
"""
import argparse
from collections import defaultdict, deque
import json
from pathlib import Path
import re
from .common import LLM, connect, database_path, experiment_identity, load_config, read_rules


def reachable(graph, roots):
    seen = set(roots)
    queue = deque(roots)
    while queue:
        for target in graph.get(queue.popleft(), []):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def source_functions(analysis):
    result = {}
    for name, record in analysis['functions'].items():
        path = Path(record['file'])
        if not path.is_file() or not record['start']:
            continue
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        ast_path = path.with_name('.cf_' + path.stem + '.json')
        ast = {}
        if ast_path.exists():
            definitions = [f for f in json.loads(ast_path.read_text())['functions'] if f['name'] == name
                           and f['overall']['end'] >= f['body']['end']]
            ast = max(definitions, key=lambda f: f['overall']['end']-f['overall']['start'], default={})
        start = ast.get('overall', {}).get('start', record['start'])
        end = ast.get('overall', {}).get('end', record['end'])
        result[name] = dict(record, start=start, end=end, ast=ast,
                            lines={n: lines[n - 1] for n in range(start, min(end, len(lines)) + 1)})
    return result


def format_code(functions, selected, line_sets=None, budget=None):
    parts = []
    total = 0
    for name in sorted(selected):
        f = functions[name]
        lines = f['lines']
        if line_sets is not None and name in line_sets:
            lines = {n: s for n, s in lines.items() if n in line_sets[name]}
        block = (f'Function: {name}\nPath: {f["file"]}:{f["start"]}\n' +
                 '\n'.join(f'{n:7}  {s}' for n, s in lines.items()))
        if budget is not None and total + len(block) > budget:
            remaining = budget - total
            if remaining <= 200:
                break
            block = block[:remaining] + '\n[... truncated ...]'
        parts.append(block)
        total += len(block)
    return '\n\n'.join(parts)


# Upper bound on source code embedded in a single model prompt. Large targets
# (e.g. Unbound) otherwise exceed the model's input context on the pruning /
# completion stages. Only reached by multi-thousand-line slices.
CODE_BUDGET = 90000


def complete_structure(f, selected):
    selected = set(selected) & set(f['lines'])
    if not selected:
        return set()
    # Preserve function signature, braces, declarations and terminating control
    # statements. Whole enclosing controls are retained conservatively; semantic
    # pruning only removes complete non-intermediary functions.
    first_body = f.get('ast', {}).get('body', {}).get('start', f['start'])
    selected.update(range(f['start'], first_body + 1))
    selected.add(f['end'])
    def visit(nodes):
        for node in nodes:
            span = node['location']['full']
            if any(span['start'] <= n <= span['end'] for n in selected):
                selected.update(range(span['start'], span['end'] + 1))
            visit(node.get('children', []))
    visit(f.get('ast', {}).get('control_flow', []))
    for n, text in f['lines'].items():
        if re.search(r'\b(return|goto|break|continue)\b|^\s*[{}]\s*$|^\s*#', text):
            selected.add(n)
    return selected


def slice_rules(config, analysis, offline=False, limit=None, missing_only=False):
    db = connect(database_path(config))
    identity = experiment_identity(config)
    llm = None if offline else LLM(config, db)
    functions = source_functions(analysis)
    if not functions:
        raise ValueError('No readable source with debug information; recompile in the current workspace')
    graph = {name: [c for c in f['calls'] if c in functions] for name, f in functions.items()}
    reverse = defaultdict(list)
    for caller, callees in graph.items():
        for callee in callees:
            reverse[callee].append(caller)
    edges = defaultdict(list)
    for a, b in analysis['edges']:
        edges[a].append(b)
    nodes = analysis['nodes']
    rules = read_rules(config['project']['rule_path'])[:limit]
    mode = ('offline-resume-conservative' if offline and missing_only else
            'offline-conservative-no-LLM' if offline else 'live-LLM')
    db.execute('INSERT OR REPLACE INTO run_metadata VALUES(?,?)', ('slicing_mode', mode))
    existing = {row[0] for row in db.execute(
        'SELECT rule_desc FROM rule_code_snippet WHERE code_snippet != ?', ('',))}
    index = '\n'.join(f'{n}: calls={",".join(graph[n])}; callers={",".join(reverse[n])}' for n in sorted(functions))
    for i, rule in enumerate(rules, 1):
        if missing_only and rule['rule'] in existing:
            continue
        print(f'Slicing rule {i}/{len(rules)}: {rule["rule"][:100]}', flush=True)
        if offline:
            handlers = {n for n in functions if rule['req_type'].lower() in n.lower() and ('handler' in n or 'unpack' in n)}
            if not handlers:
                handlers = {n for n, f in functions.items() if f['message_related']}
        else:
            def validate_selection(value):
                if not isinstance(value, dict) or not isinstance(value.get('handlers'), list):
                    raise ValueError('Expected handlers list')
                if not value['handlers'] or not set(value['handlers']) <= functions.keys():
                    raise ValueError('Handler names must come from the supplied index')
            try:
                selection = llm.query('handlers', f'''Identify entry functions that parse or handle request {rule['req_type']}.
The rule is {json.dumps(rule)}. Select all sibling parsing/handling functions needed.
Use this call graph index to propose candidates; source validation follows.
Return {{"handlers":["exact function name"],"reason":"..."}}.
{index}''', validator=validate_selection)
            except RuntimeError as error:
                fallback = {n for n, f in functions.items() if f['message_related']}
                if not fallback:
                    fallback = set(functions)
                print(f'LLM handlers fallback: {error}', flush=True)
                selection = {'handlers': sorted(fallback), 'reason': 'conservative fallback'}
            candidates = set(selection['handlers'])
            try:
                selection = llm.query('handler-source-validation', f'''Validate candidate handlers against actual source.
Rule: {json.dumps(rule)}
Return {{"handlers":["exact name"],"reason":"..."}}; choose from candidates.
{format_code(functions,candidates,budget=CODE_BUDGET)}''', validator=validate_selection)
            except RuntimeError as error:
                # The first stage already selected names from the concrete
                # call-graph index. If the model cannot restate those names,
                # retain that conservative candidate set instead of aborting
                # every subsequent rule in a full experiment.
                print(f'LLM handler-source-validation fallback: {error}', flush=True)
                selection = {'handlers': sorted(candidates), 'reason': 'conservative fallback'}
            handlers = set(selection['handlers'])
        ancestors = reachable(reverse, handlers) - handlers
        if llm and ancestors:
            context = llm.query('context', f'''For rule {json.dumps(rule)}, select upstream functions containing
connection, state, resource management or dispatch logic required to assess this rule.
Return {{"functions":["exact name"]}}. Keep uncertainty rather than discard context.
{format_code(functions,ancestors,budget=CODE_BUDGET)}''')
            context_funcs = set(context.get('functions', [])) & ancestors
        else:
            context_funcs = ancestors
        allowed = reachable(graph, handlers)
        criteria = set()
        if llm and rule['req_fields']:
            data = llm.query('criteria', f'''Find variables that represent the fields in this rule and auxiliary parsing
position/remaining-length variables. Return {{"criteria":[{{"function":"name","variable":"local or field name","lines":[1]}}]}}.
Use exact source line numbers and available names. If no criterion can be identified, return an empty list.
Rule: {json.dumps(rule)}
{format_code(functions,handlers,budget=CODE_BUDGET)}''')
            for item in data.get('criteria', []):
                name = item.get('function')
                if name not in handlers:
                    continue
                variable = item.get('variable', '')
                criteria.update(functions[name]['variables'].get(variable, []))
                valid_lines = set(item.get('lines', [])) & set(functions[name]['lines'])
                for node in nodes:
                    if node['function'] == name and (node['line'] in valid_lines or (variable and node['name'] == variable)):
                        criteria.add(node['id'])
        selected_lines = defaultdict(set)
        if criteria:
            for node_id in reachable(edges, criteria):
                node = nodes[node_id]
                if node['function'] in allowed and node['line']:
                    selected_lines[node['function']].add(node['line'])
            for name in list(selected_lines):
                selected_lines[name] = complete_structure(functions[name], selected_lines[name])
            selected = set(selected_lines) | handlers
            for name in handlers:
                if not selected_lines[name]:
                    selected_lines[name] = set(functions[name]['lines'])
            if llm:
                completion = llm.query('completion', f'''Recover semantically necessary omitted statements, including error codes,
logging and local declarations. Return {{"add_lines":{{"function":[line_numbers]}}}}.
Rule: {json.dumps(rule)}
Slice:\n{format_code(functions,selected,selected_lines,budget=CODE_BUDGET)}
Original:\n{format_code(functions,selected,budget=CODE_BUDGET)}''')
                # A malformed cached/model response must not abort the whole
                # multi-rule run; keep the conservative slice and record it.
                if not isinstance(completion, dict):
                    completion = {}
                for name, lines in completion.get('add_lines', {}).items():
                    if name in selected_lines:
                        selected_lines[name] = complete_structure(functions[name], selected_lines[name] | (set(lines) & set(functions[name]['lines'])))
        else:
            selected = allowed
            selected_lines = {n: set(functions[n]['lines']) for n in selected}
        if llm and selected:
            pruning = llm.query('pruning', f'''Identify functions semantically irrelevant to the rule or exclusively sending a
different response than {rule['res_type']!r}. Retain uncertain functions. Return {{"remove":["name"],"reason":"..."}}.
Rule: {json.dumps(rule)}
{format_code(functions,selected,selected_lines,budget=CODE_BUDGET)}''')
            if not isinstance(pruning, dict):
                pruning = {}
            remove = set(pruning.get('remove', [])) & selected - handlers
            keep = selected - remove
            # Retain intermediaries on a call path to retained functions.
            for name in list(remove):
                if (reachable(graph, [name]) - {name}) & keep:
                    remove.remove(name)
            selected -= remove
        selected |= context_funcs
        for name in context_funcs:
            selected_lines[name] = set(functions[name]['lines'])
        code = format_code(functions, selected, selected_lines)
        if not code.strip():
            raise ValueError('Refusing to store an empty slice')
        cg = '\n'.join(f'{n} -> {c}' for n in sorted(selected) for c in graph[n] if c in selected)
        # A live rerun is a new analysis checkpoint even when the textual
        # slice happens to be identical. Never carry a cached-only or stale
        # detection conclusion across that boundary. Offline resume keeps the
        # prior result for unchanged rows so it can fill only missing slices.
        if not offline:
            db.execute('UPDATE rule_code_snippet SET llm_response=? WHERE rule_desc=?', ('', rule['rule']))
        # New code invalidates any old inconsistency conclusion.
        db.execute('''INSERT INTO rule_code_snippet(rule_desc,code_snippet,call_graph) VALUES(?,?,?)
          ON CONFLICT(rule_desc) DO UPDATE SET code_snippet=excluded.code_snippet,
          call_graph=excluded.call_graph,llm_response=CASE WHEN code_snippet=excluded.code_snippet THEN llm_response ELSE '' END''',
                   (rule['rule'], code, cg))
        db.execute('INSERT OR REPLACE INTO run_metadata VALUES(?,?)',
                   ('slice:' + rule['rule'], json.dumps({'handlers': sorted(handlers), 'context': sorted(context_funcs),
                    'criteria': len(criteria), 'functions': len(selected), 'lines': sum(len(selected_lines.get(n, [])) for n in selected),
                    'mode': mode, 'indirect_calls': analysis['indirect_call_method']})))
        db.execute('INSERT OR REPLACE INTO run_metadata VALUES(?,?)',
                   ('identity:' + rule['rule'], json.dumps(identity, sort_keys=True)))
        db.commit()
    print(f'Saved {len(rules)} slices to {database_path(config)}')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', required=True)
    p.add_argument('--analysis', required=True)
    p.add_argument('--offline', action='store_true', help='Conservative slicing only; does not produce model conclusions')
    p.add_argument('--limit', type=int)
    p.add_argument('--missing-only', action='store_true',
                   help='Only fill rules without an existing nonempty slice')
    a = p.parse_args()
    slice_rules(load_config(a.config), json.loads(Path(a.analysis).read_text()),
                a.offline, a.limit, a.missing_only)


if __name__ == '__main__':
    main()
