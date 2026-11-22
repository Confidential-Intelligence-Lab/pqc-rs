"""S5.D-2 repeatable 16K-bit Cascade robustness benchmark; never exports keys."""
import argparse
import json
import random
import secrets
from s5d2_cascade_reconciliation import reconcile_cascade, CascadeError


def run(*, trials=8, n_key=16384, bit_error_rate=.02, seed=20261121):
    if type(trials) is not int or not 1 <= trials <= 100 or type(n_key) is not int or not 128 <= n_key <= 65536 or type(bit_error_rate) is not float or not 0 <= bit_error_rate <= .5:
        raise ValueError('invalid benchmark parameters')
    rng = random.Random(seed)
    rows = []
    for t in range(trials):
        a = ''.join(str(rng.randrange(2)) for _ in range(n_key))
        b = ''.join(str(int(x) ^ (rng.random() < bit_error_rate)) for x in a)
        errors = sum(x != y for x, y in zip(a, b))
        try:
            corrected, report = reconcile_cascade(
                a, b, session_id=b's5d2-local-benchmark-'+t.to_bytes(4,'big'),
                authentication_key=secrets.token_bytes(32),
                permutation_seed=secrets.token_bytes(32))
            rows.append({'trial':t,'input_errors':errors,'accepted':corrected==a,
                         'public_parity_pairs':report.public_parity_pairs,
                         'parity_disclosure_bits':report.parity_disclosure_upper_bits,
                         'confirmation_tag_bits':report.confirmation_tag_bits,
                         'authenticated_frames':report.authenticated_frames})
        except CascadeError as exc:
            rows.append({'trial':t,'input_errors':errors,'accepted':False,
                         'abort_reason':str(exc)})
    return {'stage':'S5D2_CASCADE_LOCAL_RESEARCH_BENCHMARK',
            'n_key':n_key,'trials':trials,'assumed_iid_x_error_rate':bit_error_rate,
            'accepted':sum(x['accepted'] for x in rows),
            'rows':rows,'research_only':True,
            'conditional_security_supported':False,
            'security_qualified':False,'hpke_export_authorized':False}


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--trials',type=int,default=8)
    p.add_argument('--n-key',type=int,default=16384)
    p.add_argument('--error-rate',type=float,default=.02)
    p.add_argument('--seed',type=int,default=20261121)
    a=p.parse_args()
    print(json.dumps(run(trials=a.trials,n_key=a.n_key,bit_error_rate=a.error_rate,
                         seed=a.seed),sort_keys=True,indent=2))
