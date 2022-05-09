'''
Builder
'''
# Default packages
import re
import logging
import tempfile
import subprocess
import urllib.parse
from copy import deepcopy

# 3rd-party packages

# Internal packages
from sumav.dbconnector import SumavPostgresConnector
import sumav.conf as conf

logger = logging.getLogger(__name__)


class SumavGraphManager(SumavPostgresConnector):
    def __init__(self, user, password, host, port, database=None):
        '''Connect to local RDB.

        :param str user:
        :param str password:
        :param str host:
        :param int port:
        '''
        super().__init__(user, password, 'postgres', host, port)
        self.set_remote(user, password, host, port)

    def remove_sumav_graph(self, sumav_graph_name, remote=False):
        '''Drop database given sumav_graph_name

        :param str sumav_graph_name: Target database name in local RDB
        '''
        if self.__remote['host'] and remote:
            conn_info = self.__remote
        else:
            conn_info = self._dbkwargs

        # self.__drop_db(conn, sumav_graph_name)
        proc_args = [
            'dropdb',
            '--maintenance-db=%s' % self.__make_uri(**conn_info),
            sumav_graph_name
        ]
        self.__exec(proc_args)

    def set_remote(self, user, password, host, port=5432):
        '''Set remote server.
        If you do not call this, it will connect to local database.

        :param str user:
        :param str password:
        :param str host:
        :param int port:
        '''
        self.__remote = {
            'user': user, 'password': password, 'host': host, 'port': port,
            'database': 'postgres'}

    def get_sumav_graph_list(self, remote=True):

        self._reconnect_if_closed()

        sql = 'SELECT datname FROM pg_catalog.pg_database'
        if self.__remote['host'] and remote:
            conn = self._connect(**self.__remote)
        else:
            conn = self._conn
        
        rows = self.__select_db(conn, sql)
        dbnms = [i[0] for i in rows if i[0].startswith(conf.psql_db)]
        return self.__sort_graph_list(dbnms)

    def dump_sumav_graph(
            self, sumav_graph_name, with_detection=False, remote=True):
        '''Dump a Sumav graph from source to destination with formatted
        database name like "sumav_graph_name_202101-202103"

        :param str sumav_graph_name: Target database name in remote RDB
        '''
        # Set source connection info
        if self.__remote['host'] and remote:
            src_conn_info = deepcopy(self.__remote)
            src_conn_info['database'] = sumav_graph_name
        else:
            src_conn_info = deepcopy(self._dbkwargs)
            src_conn_info['database'] = sumav_graph_name

        # Set destination connection info
        dst_conn_info = deepcopy(self._dbkwargs)
        if re.match('.*\d{6}-\d{6}$', sumav_graph_name):
            # sumav_graph_name is already dumped sumav graph
            dst_conn_info['database'] = sumav_graph_name

        else:
            date_range = self.__get_submission_date_range(src_conn_info)
            if date_range is None:
                # No data in the src database
                return None
            dst_conn_info['database'] = sumav_graph_name + '_' + date_range
            

        # Dump the src database to a local file
        with tempfile.NamedTemporaryFile() as ntf:
            # Dump src database
            proc_args = [
                'pg_dump',
                '--format=c',  # pg_restore only takes the custom format
                '--verbose',
                '--dbname=%s' % self.__make_uri(**src_conn_info),
                '--file=%s' % ntf.name,
            ]
            if not with_detection:
                proc_args.append('--table=token_*')
            self.__exec(proc_args)

            # Create empty a dst database
            proc_args = [
                'createdb',
                dst_conn_info['database'],
                # To skip pw
                '--maintenance-db=%s' % self.__make_uri(**self._dbkwargs),
                '--template=template0',
            ]
            self.__exec(proc_args)

            # Restore the local file to the dst database
            proc_args = [
                'pg_restore',
                '--no-owner',
                '--verbose',
                '--dbname=%s' % self.__make_uri(**dst_conn_info),
                 ntf.name
            ]
            self.__exec(proc_args)

        return dst_conn_info['database']

    def __exec(self, proc_args):
        logger.debug('\nshell$ %s' % ' '.join(proc_args))
        pr = subprocess.Popen(
            proc_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outputs = pr.communicate()
        if int(pr.returncode) != 0:
            raise ChildProcessError(
                'Command failed. Return code : {}'.format(pr.returncode))

        else:
            if len(outputs[0]) > 0:
                logger.debug('stdout -\n%s' % outputs[0].decode())
            if len(outputs[1]) > 0:
                logger.debug('stderr -\n%s' % outputs[1].decode())

            return True

    def __make_uri(self, user, password, host, port, database):
        return (
            'postgresql://%s:%s@%s:%s/%s'
            % (user, urllib.parse.quote_plus(password), host, port, database))

    def __get_submission_date_range(
            self, src_kwargs, to_str=True):
        '''Return submission date range in your database.

        :param bool to_str: If false return Datetime instance, else
            formatted string like 200101-200201
        '''
        connector = SumavPostgresConnector(**src_kwargs)

        with connector._conn.cursor() as cur:
            cur.execute(
                'select min("submission.date"),max("submission.date")'
                ' from detection')
            min_max = cur.fetchone()
            if min_max[0] == None or min_max[1] == None:
                return None

            if to_str:
                return '%s-%s' % (min_max[0].strftime('%y%m%d'),
                                  min_max[1].strftime('%y%m%d'))
            else:
                return min_max

    def __sort_graph_list(self, graph_list):
        return list(sorted(graph_list, key=lambda k: k[-6:], reverse=True))

    def __select_db(self, conn, sql):
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
