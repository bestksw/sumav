'''
SumavPostgresConnector
'''
# Default packages
import json
import logging
from base64 import b16decode
from datetime import timezone, datetime

# 3rd-party packages
import psycopg2
from psycopg2.extras import RealDictRow, RealDictCursor

# Internal packages
from sumav.utils import make_tokens
from sumav.dbconnector import SumavPostgresConnector

logger = logging.getLogger(__name__)


class PreprocessingBase(SumavPostgresConnector):
    _bytea_cols = ['md5', 'sha1', 'sha256']

    def __init__(self, user, password, database, host='127.0.0.1', port=5432):
        # Create database if not exist
        super().__init__(user, password, database, host, port)

        # Get column names of tables
        with self._conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute('''SELECT column_name FROM information_schema.columns
                WHERE table_catalog='%s' AND table_name='detection'
                ''' % self._dbkwargs['database'])
            self.cols = [i['column_name'] for i in c.fetchall()
                         if i['column_name'] != 'id']

    def truncate_all(self):
        with self._conn.cursor() as cur:
            cur.execute('TRUNCATE TABLE detection')
            cur.execute('TRUNCATE TABLE file_feed_log')
            cur.execute('TRUNCATE TABLE token_edge')
            cur.execute('TRUNCATE TABLE token_node')

    def detection_count(self):
        with self._conn.cursor() as c:
            # Approximate total count of rows of file_feed
            c.execute('SELECT count(*) FROM detection')
            return int(c.fetchall()[0][0])

    def commit(self):
        self._conn.commit()

    def _hex_to_bytes(self, hexstr):
        'Need to call it when use select statements'
        if hexstr is None:
            return None
        else:
            return psycopg2.Binary(b16decode(hexstr.upper()))

    def _flat_and_filter(self, dict_row, col_names):
        return self._filter(self._flat(dict_row), col_names)

    def _flat(self, dict_row, stop_keys=[]):
        out = {}
        for k, v in dict_row.items():
            if k in stop_keys:
                out[k] = json.dumps(v)
            elif type(v) in [dict, RealDictRow]:
                for k2, v2 in self._flat(v, stop_keys).items():
                    out['%s.%s' % (k, k2)] = v2
            else:
                out[k] = v

        return out

    def _filter(self, dict_row, col_names):
        return {k: v for k, v in dict_row.items() if k in col_names}

    def _make_insert_sql(self, rows, dt_pkg=None):
        vals = []
        rowcount = 0
        for row in rows:
            if len(row) == 0:
                continue
            detection = self._flat_and_filter(row, self.cols)

            # Do not insert row if no scans detect.
            none_cnt = 0
            total_cnt = 0
            for colname in detection:
                if colname.startswith('scans.'):
                    total_cnt += 1
                    if detection[colname] is None:
                        none_cnt += 1
            if none_cnt == total_cnt:
                continue

            # Change type to fit DB
            if 'submission.date' in detection:
                detection['submission.date'] = datetime.strptime(
                    detection['submission.date'], '%Y-%m-%d %H:%M:%S').replace(
                                                        tzinfo=timezone.utc)

            for key, val in detection.items():
                if val is None:
                    continue
                elif key in self._bytea_cols:
                    detection[key] = self._hex_to_bytes(val)
                elif key.startswith('scans.') and len(val) > 100:
                    detection[key] = val[:100]
                    logger.error('Truncated from %s to %s' % (val, val[:100]))

            # Make token list
            dnms = [v for k, v in detection.items() if k.startswith('scans.')]
            tokens = make_tokens(dnms, remove_duplicate=False)
            detection['tokens'] = tokens
            detection['unique_tokens'] = sorted(set(tokens))

            vals.extend([detection.get(col) for col in self.cols])
            rowcount += 1

        colfmts = '"%s"' % '","'.join(self.cols)
        valsfmts = '),('.join([','.join(['%s'] * len(self.cols))] * rowcount)
        sql = 'INSERT INTO detection (%s) VALUES (%s)' % (colfmts, valsfmts)

        # For a log
        if dt_pkg is not None:
            sql += ';INSERT INTO file_feed_log VALUES (%s, %s)'
            vals.extend([dt_pkg, self.__utcnow()])
        return sql, vals

    def __utcnow(self, remove_second=False):
        now = datetime.utcnow()
        if remove_second:
            return now.replace(second=0, microsecond=0, tzinfo=timezone.utc)
        else:
            return now.replace(tzinfo=timezone.utc)
