import json
import unittest
from portfolio import security_apps as s
from portfolio.validation import ValidationError

def event(minute, status='failure', user='alice', ip='192.0.2.10'):
    return json.dumps({'timestamp': f'2026-01-01T10:{minute:02}:00Z', 'ip': ip, 'user': user, 'status': status})

class SecurityTests(unittest.TestCase):

    def test_headers_case_insensitive_and_cookie_values_omitted(self):
        r = s.inspect_headers({'text': "CONTENT-SECURITY-POLICY: default-src 'self'; frame-ancestors 'none'\nStrict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nSet-Cookie: session=DO_NOT_ECHO; Secure; HttpOnly; SameSite=Lax"})
        self.assertEqual(r['review_count'], 0)
        self.assertNotIn('DO_NOT_ECHO', json.dumps(r))

    def test_csp_script_overrides_cannot_hide_broad_permissions(self):
        for directive in ('script-src-elem *', "script-src-attr 'unsafe-inline'"):
            report = s.inspect_headers({'text': "Content-Security-Policy: default-src 'self'; " + directive})
            finding = next((item for item in report['findings'] if item['control'] == 'Content Security Policy'))
            self.assertEqual(finding['status'], 'review')
        report = s.inspect_headers({'text': "Content-Security-Policy: default-src 'self'; script-src-elem 'none'; script-src-attr 'none'"})
        self.assertEqual(report['findings'][0]['status'], 'observed')

    def test_host_cookie_prefix_and_duplicate_attributes_are_reviewed_without_values(self):
        for attributes in ('Path=/private', 'Path=/; Domain=private.example', 'Path=/; Secure'):
            report = s.inspect_headers({'text': 'Set-Cookie: __Host-private_name=PRIVATE_VALUE; Secure; HttpOnly; SameSite=Lax; ' + attributes})
            cookie = next((item for item in report['findings'] if item['control'] == 'Cookie #1'))
            self.assertEqual(cookie['status'], 'review')
            encoded = json.dumps(report)
            for secret in ('private_name', 'PRIVATE_VALUE', 'private.example'):
                self.assertNotIn(secret, encoded)
        report = s.inspect_headers({'text': 'Set-Cookie: __Host-session=PRIVATE_VALUE; Secure; HttpOnly; SameSite=Lax; Path=/'})
        self.assertEqual(report['findings'][-1]['status'], 'observed')

    def test_hsts_large_decimal_and_leading_zeros_do_not_overflow(self):
        for lifetime, expected in [('9' * 5000, 'observed'), ('0' * 5000 + '31536000', 'observed'), ('0' * 5000 + '1', 'review')]:
            report = s.inspect_headers({'text': 'Strict-Transport-Security: max-age=' + lifetime})
            hsts = next((item for item in report['findings'] if item['control'] == 'HTTPS persistence'))
            self.assertEqual(hsts['status'], expected)

    def test_report_only_csp_does_not_count_as_enforcement(self):
        r = s.inspect_headers({'text': "Content-Security-Policy-Report-Only: default-src 'none'\nX-Frame-Options: DENY"})
        self.assertEqual(r['findings'][0]['status'], 'review')
        self.assertEqual(r['findings'][1]['status'], 'observed')

    def test_ambiguous_headers_and_broad_policies_need_review(self):
        r = s.inspect_headers({'text': 'X-Content-Type-Options: nosniff\nX-Content-Type-Options: none\nContent-Security-Policy: script-src *; frame-ancestors *\nnot a header\nStrict-Transport-Security: max-age=0'})
        self.assertEqual(r['duplicate_headers'], ['x-content-type-options'])
        self.assertEqual(r['malformed_lines'], [4])
        self.assertEqual(r['observed_count'], 0)
