#!/usr/bin/env python3
# Staging smoke test (synthetic data): python3 scripts/staging_smoke.py https://<domain> <staging passphrase>
# BOQ -> separation-of-duties refusal -> approval through the isolated signer -> PR -> PR approval.
import json, sys, urllib.request
B = sys.argv[1]; PW = sys.argv[2]
def call(m, path, tok=None, body=None):
    req = urllib.request.Request(B + path, method=m, data=json.dumps(body).encode() if body is not None else None)
    if body is not None: req.add_header('Content-Type', 'application/json')
    if tok: req.add_header('Authorization', 'Bearer ' + tok)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b'null')
def tok(p):
    s, d = call('POST', '/staging/token', body={'passphrase': PW, 'persona': p}); assert s == 200, d; return d['token']
def ok(label, res, want=(200, 201)):
    s, d = res
    print(('PASS ' if s in want else 'FAIL ') + f'{label}: {s} {json.dumps(d)[:160]}')
    if s not in want: sys.exit(1)
    return d
est, com, se, pm = tok('u-estimator'), tok('u-commercial'), tok('u-site-engineer'), tok('u-pm')
ref = ok('reference', call('GET', '/v1/p2p-reference', se))
proj = [p for p in ref['projects'] if p['code'] == 'P-001'][0]['id']
cc = ok('cost codes', call('GET', f'/v1/projects/{proj}/cost-codes', se))['cost_codes']
mat = [c for c in cc if c['code'] == '02-MAT'][0]['id']
boq = ok('BOQ create (estimator)', call('POST', '/v1/boqs', est, {'project_id': proj, 'description': 'Smoke BOQ', 'items': [
    {'item_no': '1.1', 'description': 'Reinforcement steel', 'unit': 't', 'quantity': '100', 'rate': '90000', 'cost_code_id': mat}]}))['id']
ok('BOQ submit (estimator)', call('POST', f'/v1/boqs/{boq}/submit', est, {}))
print('expect refusal:'); ok('BOQ self-approve refused (SoD)', call('POST', f'/v1/boqs/{boq}/approve', est, {}), want=(403, 409))
ok('BOQ approve (commercial manager, via signer)', call('POST', f'/v1/boqs/{boq}/approve', com, {}))
pr = ok('PR create (site engineer)', call('POST', '/v1/requisitions', se, {'project_id': proj, 'justification': 'Smoke test', 'lines': [
    {'line_no': 1, 'cost_code_id': mat, 'description': 'Steel', 'unit': 't', 'quantity': '10', 'est_unit_price': '88000'}]}))['id']
ok('PR submit', call('POST', f'/v1/requisitions/{pr}/submit', se, {}))
ok('PR approve (project manager, via signer)', call('POST', f'/v1/requisitions/{pr}/approve', pm, {}))
ok('auditor reads PR', call('GET', f'/v1/p2p/purchase_requisition/{pr}', tok('u-auditor')), want=(200, 404))
