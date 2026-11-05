"""Review-only security exception workflow; never silently suppress findings."""
from __future__ import annotations
import csv
from datetime import date
from pathlib import Path

VALID = {'Proposed', 'Rejected', 'Expired', 'Approved in fictional scenario'}


def load_exceptions(path: str | Path, as_of: date) -> list[dict]:
    with Path(path).open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    seen=set()
    for row in rows:
        code=row['exception_id']
        if code in seen or not code:
            raise ValueError('Exception IDs must be nonempty unique values')
        seen.add(code)
        if row['decision'] not in VALID:
            raise ValueError(f'Invalid exception status for {code}')
        due=date.fromisoformat(row['expires_on'])
        if row['decision']=='Approved in fictional scenario':
            if not row['fictional_approver_role'] or not row['fictional_approval_evidence']:
                raise ValueError(f'Approval without provenance: {code}')
        else:
            if row['fictional_approver_role'] or row['fictional_approval_evidence']:
                raise ValueError(f'Unapproved exception must not contain approval evidence: {code}')
        row['effective_status']= 'Expired' if due < as_of else row['decision']
        # Important: this teaching tool deliberately does NOT suppress patterns
        # even if a fictional approval were represented. Real acceptance is
        # separate from control effectiveness, policy compliance and exceptions.
        row['suppresses_finding']=False
    return rows
