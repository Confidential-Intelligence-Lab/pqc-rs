"""Independent high-precision numerical oracle for TLGR 2012 Eq. (2).

NUMERICAL REFERENCE ONLY. Does not authenticate sifting or validate device assumptions.
"""
from decimal import Decimal, localcontext


def _d(value):
    return Decimal(str(value))


def evaluate(n, k, q_tol, leak_ec, eps_sec, eps_cor, q=1):
    if not all(type(x) is int and x > 0 for x in (n, k)):
        raise ValueError('n and k must be positive integers')
    if type(leak_ec) is not int or leak_ec < 0:
        raise ValueError('leak_ec must be nonnegative integer')
    with localcontext() as ctx:
        ctx.prec = 70
        Q, s, c, quality = map(_d, (q_tol, eps_sec, eps_cor, q))
        if not (Decimal(0) <= Q < Decimal('0.5')):
            raise ValueError('q_tol must be in [0,0.5)')
        if not (Decimal(0) < s < 1 and Decimal(0) < c < 1):
            raise ValueError('epsilon inputs must be in (0,1)')
        if not (Decimal(0) < quality <= 1):
            raise ValueError('quality must be in (0,1]')
        N, K = Decimal(n), Decimal(k)
        # Equation (2), TLGR 2012. The entire factor (k+1)/k is retained.
        mu = (((N + K) / (N * K)) * ((K+1)/K) * ((Decimal(2)/s).ln())).sqrt()
        phase = Q + mu
        if phase > Decimal('0.5'):
            return {'decision':'NO_KEY', 'reason':'PHASE_BOUND_OUTSIDE_ENTROPY_DOMAIN',
                    'mu':float(mu), 'phase_error_upper':float(phase), 'maximum_numerical_key_bits':0,
                    'security_model_validated':False, 'hpke_export_authorized':False}
        h = Decimal(0) if phase == 0 else -(phase*phase.ln()+(1-phase)*(1-phase).ln())/Decimal(2).ln()
        penalty = (Decimal(2)/(s*s*c)).ln()/Decimal(2).ln()
        raw = N*(quality-h) - Decimal(leak_ec) - penalty
        maximum = max(0, int(raw.to_integral_value(rounding='ROUND_FLOOR')))
        return {'decision':'NUMERICAL_CANDIDATE' if maximum else 'NO_KEY',
                'reason':'POSITIVE_NUMERICAL_BOUND' if maximum else 'NONPOSITIVE_NUMERICAL_BOUND',
                'mu':float(mu), 'phase_error_upper':float(phase),
                'raw_bound_bits':float(raw), 'maximum_numerical_key_bits':maximum,
                'security_model_validated':False, 'hpke_export_authorized':False}
