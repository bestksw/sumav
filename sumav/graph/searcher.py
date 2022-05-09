'''
Searcher
'''
# Default packages
import math
import logging
from copy import deepcopy
from base64 import b16decode

# 3rd-party packages
import psycopg2
from psycopg2.extras import RealDictCursor

# Internal packages
import sumav.utils as utils
from sumav.dbconnector import SumavPostgresConnector

logger = logging.getLogger(__name__)


class SumavGraphSearcher(SumavPostgresConnector):
    def __init__(self, user, password, database, host, port):
        '''Connect to SumavPostgresConnector RDB

        :param int processes: Number of processors to run
        '''
        super().__init__(user, password, database, host, port)

        # Load token nodes
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT * FROM token_node')
            self.nodes = {r['token']: r for r in cur.fetchall()}
            self.alias = {tkn: r['alias'] if r['alias'] != 'None' else tkn
                          for tkn, r in self.nodes.items()}

    def get_representative_token(self, av_labels=None, tokens=None,
                                 sha256=None, md5=None, top_n=None,
                                 weight_param=4.1, general_param=225,
                                 alias=False, return_none_less_than=0):
        '''Get a representative token

        :param list av_labels:
        :param str sha256:
        :param str md5:
        :param int top_n: Get top_n tokens sort by importance.
        :return: tokens with space delimiter
        :rtype: str
        '''
        if len(self.nodes) == 0:
            raise Exception('Sumav graph does not exists.')
        self._reconnect_if_closed()

        if tokens is not None:
            pass
        elif av_labels is not None:
            tokens = utils.make_tokens(av_labels, remove_duplicate=False)
        elif sha256 is not None:
            where, vals = 'sha256=%s', [self.__hex_to_bytes(sha256)]
        elif md5 is not None:
            where, vals = 'md5=%s', [self.__hex_to_bytes(md5)]
        else:
            return None

        # Get tokens from RDB
        if tokens is None:
            with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('select tokens from detection where %s' % where,
                            vals)
                tkn_info = cur.fetchone()
                if tkn_info is None:
                    logger.info('Given hash does not exist in RDB.')
                    return None

                tokens = tkn_info['tokens']
                if tokens is None:
                    return None

        # Transform tokens to alias tokens
        if alias:
            tokens = [self.alias.get(tkn, tkn) for tkn in tokens]

        # Get token count of current detection names
        tkn_cnt = {}
        for token in tokens:
            if token in tkn_cnt:
                tkn_cnt[token] += 1
            else:
                tkn_cnt[token] = 1

        # Get tokens with information
        tkn_info_list = [self.nodes[tkn] for tkn in tkn_cnt.keys()
                         if tkn in self.nodes]

        # Select a representative token from token depends on its info
        candidates = set()
        for tkn_info in tkn_info_list:
            if tkn_info['token'] in candidates:
                continue

            candidates.add(tkn_info['token'])

        if len(candidates) > 0:
            # Calculate score to select a represenation token.
            tkn_score = {}
            for tkn in tkn_cnt.keys():
                wei_func_ret = self.__weight_func(tkn_cnt[tkn], weight_param)

                if tkn in self.nodes:
                    tki = self.nodes[tkn]
                    imp_func_ret = self.__importance_func(tki['token_count'],
                                                          tki['row_count'])
                    gen_func_ret = self.__general_func(tki['num_subsets'],
                                                       len(self.nodes),
                                                       general_param)

                    tkn_score[tkn] = wei_func_ret + imp_func_ret - gen_func_ret

                else:  # Given token not exists in Sumav graph nodes.
                    tkn_score[tkn] = wei_func_ret

            # sort by token score in decending order
            # with keeping candiate order
            out = [(tkn, tkn_score[tkn]) for tkn in candidates]
            out = sorted(out, key=lambda i: i[1], reverse=True)

            # Return tokens
            if tkn_cnt[out[0][0]] <= return_none_less_than:
                return None
            if top_n is None:
                return out[0][0]
            else:
                return out[:top_n]

    def get_related_tokens(self, token):
        '''Get related sets of token

        :param str token:
        :return: sets with information
        :rtype: dict
        '''
        self._reconnect_if_closed()

        out = {'supersets': [], 'subsets': [], 'equalsets': [], 'info': {}}
        token = token.lower()

        with self._conn.cursor(cursor_factory=RealDictCursor) as curs:
            curs.execute('SELECT * FROM token_node')
            tokens = {r['token']: r for r in curs}

            curs.execute('SELECT * FROM token_edge WHERE '
                         'token=%s or token2=%s', (token, token))

            for edge in curs:
                if token == edge['token']:
                    token2 = edge['token2']
                else:
                    token2 = edge['token']

                ret = self.compare_tokens(token, token2, without_rowcount=True)
                if ret is None:
                    continue
                elif ret['relation'] == '⊂':
                    logger.debug(' Found %s(%.2f) ⊂ %s(%.2f)' % (
                        token, ret['p(token2|token)'],
                        token2, ret['p(token|token2)']))
                    out['supersets'].append(token2)
                    out['info']['%s_%s' % (token, token2)] = ret

                elif ret['relation'] == '⊃':
                    logger.debug(' Found %s(%.2f) ⊃ %s(%.2f)' % (
                        token, ret['p(token2|token)'],
                        token2, ret['p(token|token2)']))
                    out['subsets'].append(token2)
                    out['info']['%s_%s' % (token, token2)] = ret

                elif ret['relation'] == '=':
                    # Insert token in front that is more frequently used.
                    if (tokens[token]['token_count'] >
                            tokens[token2]['token_count']):
                        logger.debug(' Found %s(%.2f) = %s(%.2f)' % (
                            token2, ret['p(token2|token)'], token,
                            ret['p(token|token2)']))
                        out['equalsets'].append(token2)
                        out['info']['%s_%s' % (token, token2)] = ret
                else:
                    pass
                    # out['notequalsets'].append(token2)

        return out

    def compare_tokens(self, token, token2, without_rowcount=False):
        '''Compare tokens which token is parent, child or brother

        :param str token:
        :param str token2:
        :param bool without_rowcount:
        :return: relation with(out) row count
        :rtype: dict
        '''
        self._reconnect_if_closed()

        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            if token == min(token, token2):
                cur.execute('select "p(token2|token)",'
                            '"p(token|token2)",intersection_row_count '
                            'from token_edge '
                            'where token=%s and token2=%s', [token, token2])
            else:
                cur.execute('select "p(token2|token)" as "p(token|token2)",'
                            '"p(token|token2)" as "p(token2|token)",'
                            'intersection_row_count from token_edge '
                            'where token=%s and token2=%s', [token2, token])
            out = cur.fetchone()
            if out is None:
                return None

            out['relation'] = self.__relation(out['p(token2|token)'],
                                              out['p(token|token2)'])

            if not without_rowcount:
                cur.execute('select row_count from token_node where token=%s',
                            [token])
                row = cur.fetchone()
                out['cnt_token'] = row['row_count']

                cur.execute('select row_count from token_node where token=%s',
                            [token2])
                out['cnt_token2'] = cur.fetchone()['row_count']

        return dict(out)

    def get_detection_rows(self, user=None, password=None, database=None,
                           host=None, port=None, sha256=None, limit=None):
        dbkwargs = deepcopy(self._dbkwargs)
        if (user is None and password is None and database is None and
                host is None and port is None):
            conn = self._conn
        else:
            if user is not None:
                dbkwargs['user'] = user
            if password is not None:
                dbkwargs['password'] = password
            if database is not None:
                dbkwargs['database'] = database
            if host is not None:
                dbkwargs['host'] = host
            if port is not None:
                dbkwargs['port'] = port
            conn = self._connect(**dbkwargs)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = ("SELECT encode(md5::bytea,'hex') as md5,"
                     "encode(sha256::bytea,'hex') as sha256,"
                     "ground_truth,tokens,sumav_label "
                     "FROM detection ")
            if sha256 is not None:
                query += "WHERE sha256=decode('%s', 'hex')" % sha256
            query += "ORDER BY id"
            if limit:
                query += " LIMIT %s" % limit
            cur.execute(query)

            total = cur.rowcount
            for i, row in enumerate(cur, 1):
                yield row
                if i % 1000 == 0:
                    logger.info('%5s/%s processed..' % (i, total))

    def get_sumav_results(self, rows, top_n=None, weight_param=4.1,
                          general_param=225, alias=False):
        logger.info('top_n=%s, weight_param=%s, general_param=%s' %
                    (top_n, weight_param, general_param))

        for row in rows:
            rep_token = self.get_representative_token(
                tokens=row['tokens'], top_n=top_n, weight_param=weight_param,
                general_param=general_param, alias=alias)

            # if rep_token is not None:
            yield {'sha256': row['sha256'], 'md5': row['md5'],
                    'ground_truth': row['ground_truth'],
                    'sumav_label': rep_token}

    def update_sumav_results(self, rows, user=None, password=None,
                             database=None, host=None, port=None, sha256=None):
        vals = []
        sql = ('UPDATE detection SET sumav_label=t.token '
               'from (values %s) as t(md5, token) '
               'where detection.md5=t.md5')

        dbkwargs = deepcopy(self._dbkwargs)
        if (user is None and password is None and database is None and
                host is None and port is None):
            conn = self._conn
        else:
            if user is not None:
                dbkwargs['user'] = user
            if password is not None:
                dbkwargs['password'] = password
            if database is not None:
                dbkwargs['database'] = database
            if host is not None:
                dbkwargs['host'] = host
            if port is not None:
                dbkwargs['port'] = port
            conn = self._connect(**dbkwargs)

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for i, row in enumerate(rows, 1):
                vals.extend([self.__hex_to_bytes(row['md5']),
                             row['sumav_label']])
                if i % 1000 == 0:
                    fmt_sql = sql % ','.join(['(%s,%s)']*int(len(vals)/2))
                    cur.execute(fmt_sql, vals)
                    conn.commit()

            if len(vals) > 0:
                fmt_sql = sql % ','.join(['(%s,%s)']*int(len(vals)/2))
                cur.execute(fmt_sql, vals)
                conn.commit()

    def get_metrics(self, rows=None, alias=False):
        gt_dict, out_dict = {}, {}
        skipped = 0
        if rows is None:
            with self._conn.cursor() as curs:
                curs.execute("SELECT encode(sha256::bytea,'hex'),ground_truth,"
                             "sumav_label FROM detection ORDER BY id")
                for row in curs:
                    if row[2] is None:
                        skipped += 1
                        continue
                    gt_dict[row[0]] = row[1]
                    out_dict[row[0]] = row[2].split(' ')[0]

        else:
            for row in rows:
                if row['sumav_label'] is None:
                    skipped += 1
                    continue

                if alias:
                    gt = self.alias.get(row['ground_truth'],
                                        row['ground_truth'])
                else:
                    gt = row['ground_truth']
                gt_dict[row['sha256']] = gt
                out_dict[row['sha256']] = row['sumav_label'].split(' ')[0]

        precision, recall, fmeasure = (
            utils.eval_precision_recall_fmeasure(gt_dict, out_dict))
        return {'precision': precision,
                'recall': recall,
                'fmeasure': fmeasure,
                'skipped': skipped}

    def get_graph(self, sha256=None, md5=None):
        'Get graph with dictionary form with given hash'
        self._reconnect_if_closed()

        if sha256 is not None:
            where, vals = 'sha256=%s', [self.__hex_to_bytes(sha256)]
        elif md5 is not None:
            where, vals = 'md5=%s', [self.__hex_to_bytes(md5)]
        else:
            return None

        with self._conn.cursor() as curs:
            graph = {}
            curs.execute('select distinct(tokens) from detection where %s' %
                         where, vals)
            tokens = sorted(set(curs.fetchone()[0]))
            for i, tkn1 in enumerate(tokens, 1):
                for tkn2 in tokens[i:]:
                    ret = self.compare_tokens(tkn1, tkn2)
                    if ret is None:
                        continue
                    elif ret['relation'] == '⊃':
                        self.__update_graph(graph, tkn1, tkn2)

                    elif ret['relation'] == '⊂':
                        self.__update_graph(graph, tkn2, tkn1)

                    elif ret['relation'] == '=':
                        self.__update_graph(graph, tkn1, tkn2)
                        self.__update_graph(graph, tkn2, tkn1)

            return graph

    def __relation(self, ratio_token, ratio_token2, intersection_ratio=0.9):
        '''Return relation symbol between tokens.

        A = B: A equals B
        A ⊂ B: B includes A
        A ⊃ B: A includes B
        A ! B: A and B are completely different.
        A $ B: A and B are slightly different.
        '''
        if ratio_token > intersection_ratio:
            if ratio_token2 > intersection_ratio:
                return '='
            else:
                return '⊂'
        elif ratio_token < 1 - intersection_ratio:
            if ratio_token2 < 1 - intersection_ratio:
                return '!'
            elif ratio_token2 > intersection_ratio:
                return '⊃'
            else:
                return '$'
        else:
            if ratio_token2 > intersection_ratio:
                return '⊃'
            else:
                return '$'

    def __update_graph(self, graph, supertoken, subtoken):
        if supertoken in graph:
            graph[supertoken].append(subtoken)
        else:
            graph[supertoken] = [subtoken]

    def __hex_to_bytes(self, hexstr):
        'Need to call it when use select statements'
        if hexstr is None:
            return None
        else:
            return psycopg2.Binary(b16decode(hexstr.upper()))

    def __importance_func(self, token_count, row_count):
        return token_count / row_count

    def __general_func(self, num_subsets, num_nodes, general_param):
        return num_subsets / num_nodes * general_param

    def __weight_func(self, token_count, weight_param):
        if weight_param > 1:
            return math.log(token_count, weight_param)
        else:
            return 0
