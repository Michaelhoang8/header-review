from . import security_apps
from .validation import ValidationError

def table(title, headers, rows):
    return {'title': title, 'headers': headers, 'rows': rows}

def enrich(path, data, result):
    """Attach diagnostics without changing existing response fields."""
    tables, notes = ([], [])
    baseline = data.get('baseline_text', '')
    if not isinstance(baseline, str):
        raise ValidationError('baseline_text must be text')
    if baseline.strip():
        old = security_apps.inspect_headers({'text': baseline})
        before = {f['control']: f['status'] for f in old['findings']}
        after = {f['control']: f['status'] for f in result['findings']}
        rows = []
        for control in sorted(set(before) | set(after)):
            a, b = (before.get(control, 'absent'), after.get(control, 'absent'))
            change = 'unchanged' if a == b else 'regression' if a == 'observed' and b != 'observed' else 'improvement' if b == 'observed' else 'changed'
            rows.append([control, a, b, change])
        tables = [table('Policy baseline comparison', ['Control', 'Baseline', 'Current', 'Change'], rows)]
        notes = ['Compares heuristic statuses, not raw header values. Cookie controls are compared by ordinal position; changing cookie order can change their correspondence.']
    else:
        notes = ['Paste an optional baseline header block to identify improvements and regressions. Header and cookie values are never included in the comparison report.']
    if tables or notes:
        result['capabilities'] = {'tables': tables, 'notes': notes}
    return result
