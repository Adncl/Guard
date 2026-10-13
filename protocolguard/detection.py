"""Three independent analyses followed by evidence-grounded synthesis."""
import argparse
import json
from pathlib import Path
import re
from .common import LLM, connect, database_path, experiment_identity, load_config, read_rules
from .slicing import source_functions, format_code

# Upper bound on slice text embedded in a detection prompt. Large targets
# (e.g. Unbound) store multi-thousand-line slices that would otherwise exceed
# the reasoning model's input context.
CODE_BUDGET = 40000


def truncate_code(code, budget=CODE_BUDGET):
    """Cut slice text to a prefix at a function boundary for the model prompt.

    Validation still runs against the full slice, so a response may only cite
    locations the model actually observed.
    """
    if len(code) <= budget:
        return code
    cut = code[:budget]
    boundary = cut.rfind('\n\nFunction: ')
    if boundary > 0:
        cut = cut[:boundary]
    return cut + '\n[... slice truncated for model context ...]'


def validate_report(report, code):
    if not isinstance(report, dict) or report.get('result') not in ('violation found!', 'no violation found!', 'inconclusive'):
        raise ValueError('Invalid inconsistency result')
    if not isinstance(report.get('reason'), str) or not report['reason'].strip():
        raise ValueError('Missing explanation')
    if report['result'] == 'violation found!':
        violations = report.get('violations')
        if not isinstance(violations, list) or not violations:
            raise ValueError('A violation needs source evidence')
        blocks = re.split(r'(?m)^Function: ', code)[1:]
        by_name = {block.splitlines()[0]: block for block in blocks}
        for violation in violations:
            block = by_name.get(violation.get('function_name'), '')
            if not block or f'Path: {violation.get("filename")}:' not in block:
                raise ValueError('Hallucinated source location')
            lines = {int(n) for n in re.findall(r'(?m)^\s*(\d+)\s{2}', block)}
            requested = violation.get('code_lines', [])
            if not isinstance(requested, list) or not all(type(n) is int for n in requested):
                raise ValueError('code_lines must be a JSON array of integer source line numbers, e.g. [875, 879], not source code strings')
            if not requested or not set(requested) <= lines:
                raise ValueError('Violation line numbers must exist in the supplied slice')


def detect(config, limit=None, replace=False, cached_only=False):
    db = connect(database_path(config))
    rows = db.execute('SELECT rule_desc,code_snippet,llm_response FROM rule_code_snippet').fetchall()
    active_rules = {rule['rule'] for rule in read_rules(config['project']['rule_path'])}
    rows = [row for row in rows if row[0] in active_rules]
    if not rows:
        raise ValueError('No slices: run program slicing first')
    identity = experiment_identity(config)
    for rule, _, _ in rows:
        stored = db.execute('SELECT value FROM run_metadata WHERE key=?', ('identity:' + rule,)).fetchone()
        if not stored or json.loads(stored[0]) != identity:
            raise ValueError('Slice provenance is missing or stale; rerun the slice stage before detection')
    if cached_only:
        for rule, code, previous in rows[:limit]:
            if (previous and not replace and json.loads(previous).get('result') != 'inconclusive'
                    and json.loads(previous).get('provenance', {}).get('identity') == identity):
                continue
            final = {
                'result': 'inconclusive',
                'reason': 'LLM unavailable in cached-only mode; no compliance conclusion was generated.',
                'violations': [],
                'provenance': {'mode': 'cached-only-no-LLM', 'identity': identity,
                               'dynamically_verified': False},
            }
            db.execute('UPDATE rule_code_snippet SET llm_response=? WHERE rule_desc=?',
                       (json.dumps(final, ensure_ascii=False), rule))
        db.commit()
        print('Recorded inconclusive cached-only results; no LLM conclusions were fabricated.', flush=True)
        return
    llm = LLM(config, db)
    count = config['llm'].get('llm_violation_repeat_times', 3)
    if count < 1:
        raise ValueError('llm_violation_repeat_times must be positive')
    for rule, code, previous in rows[:limit]:
        if (previous and not replace and json.loads(previous).get('result') != 'inconclusive'
                and json.loads(previous).get('provenance', {}).get('identity') == identity):
            continue
        observation_start = len(llm.observations)
        prompt = f'''Audit {config['project']['protocol_name']} {config['project']['protocol_version']} compliance.
Understand the rule, inspect control flow and data processing, then identify a concrete violation or explain compliance.
Missing code in a slice is not evidence of missing validation in the full program. Use inconclusive when context is inadequate.
Return JSON with result ("violation found!", "no violation found!", or "inconclusive"), reason,
and violations (list of {{"function_name":"exact name","filename":"exact Path without line suffix","code_lines":[123,124]}}).
code_lines MUST contain integer source line numbers from the left column, never strings or source code text.
For a violation all locations must appear in the supplied code. Do not introduce requirements from unrelated rules.
Rule: {rule}
SliceCode:\n{truncate_code(code)}'''
        for refinement in range(3):
            validator = lambda value: validate_report(value, code)
            responses = [llm.query('inconsistency', prompt, reasoning=True, validator=validator, sample=i) for i in range(count)]
            final = llm.query('self-consistency', prompt + '\nSynthesize ALL independent analyses below. Verify each claim against the original code and rule, resolve disagreements, and return the same JSON schema.\n' +
                              json.dumps(responses, ensure_ascii=False), reasoning=True, validator=validator)
            if final['result'] != 'inconclusive' or refinement == 2:
                break
            analysis_path = database_path(config).parent / 'analysis.json'
            if not analysis_path.exists():
                break
            functions = source_functions(json.loads(analysis_path.read_text()))
            present = set(re.findall(r'(?m)^Function: (.+)$', code))
            available = sorted(functions.keys() - present)
            expansion = llm.query('missing-context', f'''The compliance analysis needs more source context.
Rule: {rule}
Analysis: {json.dumps(final)}
Available additional function definitions: {json.dumps(available)}
Choose up to 20 exact function names needed to settle the missing evidence. For an ordering constraint,
other message handlers may establish whether a forbidden message is accepted. Return {{"functions":["name"]}}.''')
            names = set(expansion.get('functions', [])) & set(available)
            if not names:
                break
            additional = format_code(functions, names, budget=CODE_BUDGET)
            code += '\n\n' + additional
            prompt += '\nAdditional source context (exact original definitions):\n' + additional
            db.execute('UPDATE rule_code_snippet SET code_snippet=?,llm_response=? WHERE rule_desc=?', (code, '', rule))
            db.commit()
            print(f'Expanded missing context with {len(names)} function definitions', flush=True)
        final['provenance'] = {'mode': 'LLM-with-cache', 'requested_model': llm.reasoning,
                               'analyses': count, 'identity': identity,
                               'model_calls': llm.observations[observation_start:],
                               'dynamically_verified': False}
        db.execute('UPDATE rule_code_snippet SET llm_response=? WHERE rule_desc=?', (json.dumps(final, ensure_ascii=False), rule))
        db.commit()
        print(f'{final["result"]}: {rule[:100]}', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default=str(Path(__file__).resolve().parents[1] / 'config/config.toml'))
    p.add_argument('--limit', type=int)
    p.add_argument('--replace', action='store_true')
    p.add_argument('--cached-only', action='store_true',
                   help='Record inconclusive results for uncached rules without calling an LLM')
    a = p.parse_args()
    detect(load_config(a.config), a.limit, a.replace, a.cached_only)


if __name__ == '__main__':
    main()
