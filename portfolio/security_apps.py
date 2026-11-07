import re
from collections import defaultdict
from .validation import ValidationError

def source(data):
    value = data.get('text')
    if not isinstance(value, str) or not value.strip() or len(value.encode('utf-8')) > 500000:
        raise ValidationError('Provide nonempty text of at most 500 KB')
    if len(value.splitlines()) > 5000:
        raise ValidationError('Limit input to 5,000 lines')
    return value

def inspect_headers(data):
    text = source(data)
    headers = defaultdict(list)
    malformed = []
    for line, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith('HTTP/'):
            continue
        name, separator, value = raw.partition(':')
        if not separator or not re.fullmatch("[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            malformed.append(line)
            continue
        headers[name.lower()].append(value.strip())
    findings = []

    def add(control, status, detail, action):
        findings.append(dict(control=control, status=status, detail=detail, action=action))
    duplicates = sorted((name for name, values in headers.items() if len(values) > 1 and name != 'set-cookie'))

    def one(name):
        return headers[name][0] if len(headers[name]) == 1 else ''
    csp = one('content-security-policy')
    directives = {}
    duplicate_directive = False
    for part in csp.split(';'):
        tokens = part.split()
        if tokens:
            key = tokens[0].lower()
            duplicate_directive |= key in directives
            directives.setdefault(key, tokens[1:])
    script = directives.get('script-src', directives.get('default-src'))
    script_policies = [script, directives.get('script-src-elem', script), directives.get('script-src-attr', script)]
    csp_ok = bool(csp) and (not duplicate_directive) and all((policy is not None and (not any((token in ("'unsafe-inline'", "'unsafe-eval'", '*', 'data:', 'http:', 'https:') for token in policy))) for policy in script_policies))
    add('Content Security Policy', 'observed' if csp_ok else 'review', 'Restrictive script-source syntax observed' if csp_ok else 'Missing, ambiguous, or broad script policy', 'Review a nonce/hash-based CSP against application requirements; this is a heuristic, not browser policy validation.')
    frame = directives.get('frame-ancestors', [])
    frame_ok = frame in (["'none'"], ["'self'"])
    xfo_ok = one('x-frame-options').upper() in ('DENY', 'SAMEORIGIN')
    add('Framing policy', 'observed' if frame_ok or (not frame and xfo_ok) else 'review', 'Restrictive framing header observed' if frame_ok or (not frame and xfo_ok) else 'No unambiguous self-only or deny framing policy found', 'Use CSP frame-ancestors with the embedding origins your application requires.')
    hsts = one('strict-transport-security')
    ages = re.findall('(?:^|;)\\s*max-age\\s*=\\s*([0-9]+)\\s*(?=;|$)', hsts, re.I)
    age = ages[0].lstrip('0') or '0' if len(ages) == 1 else ''
    strong_hsts = len(ages) == 1 and (len(age) > 8 or (len(age) == 8 and age >= '31536000'))
    add('HTTPS persistence', 'observed' if strong_hsts else 'review', 'HSTS max-age of at least one year observed' if strong_hsts else 'Missing, ambiguous, or short HSTS lifetime', 'Only use HSTS on HTTPS. Validate HTTPS support before choosing a long lifetime or includeSubDomains.')
    add('MIME sniffing', 'observed' if one('x-content-type-options').lower() == 'nosniff' else 'review', 'nosniff observed' if one('x-content-type-options').lower() == 'nosniff' else 'nosniff not observed', 'Serve correct Content-Type values and add X-Content-Type-Options: nosniff.')
    referrer = one('referrer-policy').lower()
    referrer_ok = referrer in ('no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin')
    add('Referrer policy', 'observed' if referrer_ok else 'review', 'Restrictive referrer policy observed' if referrer_ok else 'Review absent, complex, or permissive policy', 'Choose a Referrer-Policy appropriate for the data in page URLs.')
    for index, cookie in enumerate(headers.get('set-cookie', []), 1):
        parts = [part.strip() for part in cookie.split(';')[1:] if part.strip()]
        names = [part.split('=', 1)[0].lower() for part in parts]
        attrs = {part.split('=', 1)[0].lower(): part.partition('=')[2].lower() for part in parts}
        missing = [key for key in ('secure', 'httponly') if key not in attrs]
        if attrs.get('samesite') not in ('lax', 'strict', 'none'):
            missing.append('valid SameSite')
        if len(names) != len(set(names)):
            missing.append('duplicate attributes')
        cookie_name = cookie.partition('=')[0].strip()
        if cookie_name.startswith('__Host-') and ('domain' in attrs or attrs.get('path') != '/'):
            missing.append('host-prefix requires Path=/ and no Domain')
        add(f'Cookie #{index}', 'review' if missing else 'observed', 'Review: ' + ', '.join(missing) if missing else 'Secure, HttpOnly, and SameSite attributes observed', 'Assess each cookie by purpose; session cookies generally need Secure and HttpOnly. SameSite=None requires Secure.')
    return {'findings': findings, 'review_count': sum((f['status'] == 'review' for f in findings)), 'observed_count': sum((f['status'] == 'observed' for f in findings)), 'duplicate_headers': duplicates, 'malformed_lines': malformed, 'note': 'Offline heuristic review only. Does not verify TLS, header delivery, CSP validity, or exploitability. Header and cookie values are omitted from reports.'}
