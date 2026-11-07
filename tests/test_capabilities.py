import json
import csv
import io
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from portfolio import capabilities as c, security_apps as security
from portfolio.db import initialize, connect, SCHEMA
from portfolio.validation import ValidationError, NotFoundError

def enhanced(path, data, function):
    return c.enrich(path, data, function(data))

class AnalysisCapabilities(unittest.TestCase):

    def test_header_regression_and_no_header_values_returned(self):
        data = {'text': 'X-Content-Type-Options: wrong', 'baseline_text': 'X-Content-Type-Options: nosniff\nAuthorization: PRIVATE_VALUE'}
        r = enhanced('/api/security/headers', data, security.inspect_headers)
        row = next((row for row in r['capabilities']['tables'][0]['rows'] if row[0] == 'MIME sniffing'))
        self.assertEqual(row[-1], 'regression')
        self.assertNotIn('PRIVATE_VALUE', json.dumps(r))
if __name__ == '__main__':
    unittest.main()
