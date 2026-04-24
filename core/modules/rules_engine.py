"""Simple rule engine for custom triage detections.

Rule schema:
{
  "name": "packed_entropy_sparse_imports",
  "all": [
    ["stats.sections.high_entropy_sections_count", ">=", 1],
    ["stats.imports_total", "<", 10]
  ],
  "severity": "high",
  "tag": "packed_binary_suspected",
  "message": "High entropy with sparse imports"
}
"""

from __future__ import annotations

from typing import Any, Dict, List


def _get_path(obj: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = obj
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _cmp(lhs: Any, op: str, rhs: Any) -> bool:
    if op == '==':
        return lhs == rhs
    if op == '!=':
        return lhs != rhs
    if op == '>':
        return lhs > rhs
    if op == '>=':
        return lhs >= rhs
    if op == '<':
        return lhs < rhs
    if op == '<=':
        return lhs <= rhs
    if op == 'contains':
        return isinstance(lhs, (str, list, dict)) and rhs in lhs
    raise ValueError(f'unsupported operator: {op}')


def evaluate_rules(context: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for rule in rules:
        all_expr = rule.get('all', [])
        any_expr = rule.get('any', [])

        all_ok = all(_cmp(_get_path(context, p), op, val) for p, op, val in all_expr) if all_expr else True
        any_ok = any(_cmp(_get_path(context, p), op, val) for p, op, val in any_expr) if any_expr else True

        if all_ok and any_ok:
            hits.append(
                {
                    'name': rule.get('name', 'unnamed_rule'),
                    'severity': rule.get('severity', 'medium'),
                    'tag': rule.get('tag', 'custom_rule_hit'),
                    'message': rule.get('message', ''),
                }
            )
    return hits
