'''
SumavPostgresConnector
'''
# Default packages
import os
import json
import logging
import platform
import subprocess
from base64 import b16decode

# 3rd-party packages
import psycopg2
from psycopg2.extras import RealDictRow

# Internal packages

logger = logging.getLogger(__name__)


class SumavPostgresConnector:
    def __init__(self, user, password, database, host, port):
        '''Connect to Sumav RDB

        :param str user:
        :param str password:
        :param str database:
        :param str host:
        :param int port:
        '''
        self._dbkwargs = {k: v for k, v in locals().items() if k != 'self'}
        self.__create_db(user, password, database, host, port)
        self._conn = self._connect(**self._dbkwargs)
        if self.__create_tables_if_not_exists():
            self._conn.close()
            self._conn = self._connect(**self._dbkwargs)

    def _connect(self, user, password, database, host, port):
        return psycopg2.connect(user=user, password=password,
                                database=database, host=host, port=port,
                                application_name='sumav@%s' % platform.node())

        # Convert PostgreSQL byte type to hex string automatically from cursor
        hextype = psycopg2.extensions.new_type(
            psycopg2.BINARY.values, 'HEX',
            lambda value, curs: value[2:] if value is not None else None)
        psycopg2.extensions.register_type(hextype)

        # Set timezone
        with self.__conn.cursor() as c:
            c.execute("set timezone to 'UTC'")

    def _reconnect_if_closed(self):
        try:
            with self._conn.cursor() as c:
                c.execute('select 1')

        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            self._conn = self._connect(**self._dbkwargs)

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

    def __create_db(self, user, password, database, host, port):
        pr = subprocess.Popen(['createdb', database,
                               '--host=%s' % host,
                               '--port=%s' % port,
                               '--username=%s' % user,
                               '--maintenance-db=postgres',
                               '--template=template0'],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              env={'PGPASSWORD': password})
        _, err = pr.communicate()
        if int(pr.returncode) != 0 and int(pr.returncode) != 1:
            msg = '%s(RetCode: %s)' % (err.decode(), pr.returncode)
            logger.error(msg)
            raise Exception(msg)

    def __create_tables_if_not_exists(self):
        here = os.path.abspath(os.path.dirname(__file__)) + '/'  # Script based
        with self._conn.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema='public' AND "
                        "table_type='BASE TABLE'")
            if cur.rowcount == 0:
                with open(here + 'schema.sql', 'r') as f:
                    sql = f.read().replace('sumav', self._dbkwargs['user'])
                    cur.execute(sql)
                self._conn.commit()
                logger.info('New tables created.')
                return True

        return False

    def close(self):
        self._conn.close()
