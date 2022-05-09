'''
Builder
'''
# Default packages
import time
import logging
from difflib import SequenceMatcher

# 3rd-party packages
from psycopg2.extras import RealDictCursor

# Internal packages
import sumav.conf as conf
from sumav.dbconnector import SumavPostgresConnector

logger = logging.getLogger(__name__)


class SumavGraphBuilder(SumavPostgresConnector):
    __batch_size = 100000

    def __init__(self, user, password, database, host, port):
        '''Connect to SumavPostgresConnector RDB

        :param int processes: Number of processors to run
        '''
        super().__init__(user, password, database, host, port)

    def get_graph_size(self):
        with self._conn.cursor() as cur:
            cur.execute('SELECT count(*) FROM token_edge')
            edge_size = cur.fetchone()[0]
            cur.execute('SELECT count(*) FROM token_node')
            node_size = cur.fetchone()[0]
        
        return {'edge_size': edge_size, 'node_size': node_size}

    def build_graph(self):
        self._reconnect_if_closed()
        totalsec = 0
        nodes, edges = {}, {}
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('TRUNCATE TABLE token_edge,token_node')

        started = time.time()
        logger.info('[Step 1/4] Build token graph.')
        affected = self.__build_token_graph(nodes, edges)
        elapsed = time.time() - started
        totalsec += elapsed
        logger.info('%.2fs elapsed to build token graph..' % elapsed)
        if affected == 0:
            logger.info('Total %.2fs elapsed.' % totalsec)
            return

        started = time.time()
        logger.info('[Step 2/4] Calculate conditional probabilities of edges.')
        self.__calculate_conditional_probabilities(nodes, edges)
        elapsed = time.time() - started
        totalsec += elapsed
        logger.info('%.2fs elapsed to calcuate conditional probabilites '
                    'between nodes..' % elapsed)

        started = time.time()
        logger.info('[Step 3/4] Calculate relations between nodes.')
        self.__calculate_relations(nodes, edges)
        elapsed = time.time() - started
        totalsec += elapsed
        logger.info('%.2fs elapsed to calcaulate relations.' % elapsed)

        started = time.time()
        logger.info('[Step 4/4] Insert nodes and edges in RDB.')
        self.__insert_nodes_and_edges(nodes, edges)
        elapsed = time.time() - started
        totalsec += elapsed
        logger.info('%.2fs elapsed to insert nodes and edges..' % elapsed)

        self._conn.commit()
        logger.info('Total %.2fs elapsed.' % totalsec)

    def __build_token_graph(self, nodes, edges, min_token_len=4):
        node_max_id = self.__get_max_id(nodes)
        edge_max_id = self.__get_max_id(edges)

        with self._conn.cursor() as cur:
            cur.execute('SELECT count(*) FROM detection')
            len_detections = cur.fetchone()[0]
            if len_detections == 0:
                logger.info('No rows in the detection table.')
                return 0

        logger.info('Start building nodes of the graph.')
        with self._conn.cursor('srvcur', cursor_factory=RealDictCursor) as cur:
            # Increment count values of nodes and edges of token graph
            cur.itersize = self.__batch_size
            cur.execute('SELECT * FROM detection ORDER BY id')
            for i, detection in enumerate(cur, 1):
                last_detection_id = detection['id']
                if i % self.__batch_size == 0:
                    logger.info('%9d/%s detection processed. '
                                '([count] node: %s, edge :%s)' %
                                (i, len_detections, len(nodes), len(edges)))

                if detection['tokens'] is None:
                    continue

                # Update token count on token_node table
                tkn_cnt = {}
                for tkn in detection['tokens']:
                    if len(tkn) < min_token_len:
                        continue

                    if tkn in tkn_cnt:
                        tkn_cnt[tkn] += 1
                    else:
                        tkn_cnt[tkn] = 1

                for tkn, cnt in tkn_cnt.items():
                    if tkn in nodes:
                        nodes[tkn]['token_count'] += cnt
                        nodes[tkn]['row_count'] += 1
                    else:
                        node_max_id += 1
                        nodes[tkn] = {'id': node_max_id, 'token': tkn,
                                      'alias': None, 'parents': [],
                                      'token_count': cnt,
                                      'row_count': 1, 'token_ratio': None,
                                      'num_subsets': None}

            logger.info('%9d/%s detection processed. '
                        '([count] node: %s, edge :%s)' %
                        (i, len_detections, len(nodes), len(edges)))

            # Remove rare tokens or not widely used tokens
            total_tkn_cnt = len(nodes)
            removed_cnt = 0
            for val in list(nodes.values()):
                if (val['token_count'] / total_tkn_cnt < 0.0000001 or
                        val['token_count'] / val['row_count'] == 1):
                    del nodes[val['token']]
                    removed_cnt += 1
            logger.info('%s rare nodes are removed.' % removed_cnt)

        logger.info('Start building edges of the graph.')
        with self._conn.cursor('srvcur', cursor_factory=RealDictCursor) as cur:
            # Update edge count on token_edge table
            cur.itersize = self.__batch_size
            cur.execute('SELECT * FROM detection WHERE id<=%s ORDER BY id' %
                        last_detection_id)
            for i, detection in enumerate(cur, 1):
                if i % self.__batch_size == 0:
                    logger.info('%9d/%s detection processed. '
                                '([count] node: %s, edge :%s)' %
                                (i, len_detections, len(nodes), len(edges)))

                if detection['tokens'] is None:
                    continue

                for j, tkn in enumerate(detection['unique_tokens']):
                    if tkn not in nodes:
                        continue

                    for tkn2 in detection['unique_tokens'][j + 1:]:
                        if tkn2 not in nodes:
                            continue

                        min_tkn, max_tkn = min(tkn, tkn2), max(tkn, tkn2)
                        key = '%s_%s' % (min_tkn, max_tkn)
                        if key in edges:
                            edges[key]['intersection_row_count'] += 1
                        else:
                            edge_max_id += 1
                            edges[key] = {
                                'id': edge_max_id, 'token': min_tkn,
                                'token2': max_tkn, 'p(token2|token)': None,
                                'p(token|token2)': None,
                                'intersection_row_count': 1}\

            logger.info('%9d/%s detection processed. '
                        '([count] node: %s, edge :%s)' %
                        (i, len_detections, len(nodes), len(edges)))

        return i

    def __calculate_conditional_probabilities(self, nodes, edges):
        # Update conditional probabilities in token edges
        for i, edge in enumerate(edges.values(), 1):
            if i % self.__batch_size == 0:
                logger.info('%9s/%s token_edge processed.' % (i, len(edges)))

            try:
                edge['p(token2|token)'] = (edge['intersection_row_count'] /
                                           nodes[edge['token']]['row_count'])
                edge['p(token|token2)'] = (edge['intersection_row_count'] /
                                           nodes[edge['token2']]['row_count'])
            except Exception as e:
                logger.error(str(e))

        # Update token_ratio in token nodes
        total = sum([n['token_count'] for n in nodes.values()])
        for i, node in enumerate(nodes.values(), 1):
            if i % self.__batch_size == 0:
                logger.info('%9s/%s token_node processed.' % (i, len(edges)))

            node['token_ratio'] = node['token_count'] / total
            node['num_subsets'] = 0  # Will be updated below

    def __calculate_relations(self, nodes, edges):
        alias_graph = {k: None for k in nodes.keys()}
        for i, edge in enumerate(edges.values(), 1):
            if i % self.__batch_size == 0:
                logger.info('%9s/%s relation calculated.' % (i, len(edges)))

            if (edge['p(token2|token)'] >= conf.intersection_ratio and
                    edge['p(token|token2)'] >= conf.intersection_ratio):
                # Update alias graph
                t1 = nodes[self.__get_major_alias(alias_graph, edge['token'])]
                t2 = nodes[self.__get_major_alias(alias_graph, edge['token2'])]

                if t1['token'] == t2['token']:
                    continue
                elif t1['token_count'] >= t2['token_count']:
                    alias_graph[t2['token']] = t1['token']
                else:
                    alias_graph[t1['token']] = t2['token']

            elif edge['p(token|token2)'] >= conf.intersection_ratio:
                # Update num_subsets and parents
                nodes[edge['token']]['num_subsets'] += 1

                # Future work: Find parents by using string similarity
                similarity = SequenceMatcher(a=edge['token'],
                                             b=edge['token2']).ratio()
                if similarity < 0.65:
                    nodes[edge['token2']]['parents'].append(edge['token'])
                else:
                    if edge['token'] != edge['token2']:
                        nodes[edge['token2']]['alias'] = edge['token']

            elif edge['p(token2|token)'] >= conf.intersection_ratio:
                # Update num_subsets and parents
                nodes[edge['token2']]['num_subsets'] += 1

                # Future work: Find parents by using string similarity
                similarity = SequenceMatcher(a=edge['token'],
                                             b=edge['token2']).ratio()
                if similarity < 0.65:
                    nodes[edge['token']]['parents'].append(edge['token2'])
                else:
                    if edge['token'] != edge['token2']:
                        nodes[edge['token']]['alias'] = edge['token2']

        # Update current alias to major alias by referring to the alias graph
#         for token, alias in alias_graph.items():
#             if alias is not None:
#                 nodes[token]['alias'] = self.__get_major_alias(alias_graph,
#                                                                alias)

        # Remove ancestors from parents of nodes
#         for node in nodes.values():
#             ancestors = self.__get_all_ancestors(nodes, node['token'])
#             node['parents'] = [x for x in node['parents']
#                                if x not in ancestors]

        # Find attribute groups (same parents and mutully exclusive)
#         parents_grp = {}
#         for node in nodes.values():
#             if not node['parents']:
#                 continue
#
#             for parent in node['parents']:
#                 if parent not in parents_grp:
#                     parents_grp[parent] = [node['token']]
#                 else:
#                     parents_grp[parent].append(node['token'])
#
#         attr_grp = {}
#         for parent, children in parents_grp.items():
#             if len(children) <= 1:
#                 continue
#
#             self.__get_mutully_exclusive_groups(edges, children)

#     def __get_mutully_exclusive_groups(self, edges, tokens):
#         grp = {tkn: [] for tkn in tokens}
#         for i, tkn in enumerate(tokens, 1):
#             for tkn2 in tokens[i:]:
#                 min_tkn, max_tkn = min(tkn, tkn2), max(tkn, tkn2)
#                 key = '%s_%s' % (min_tkn, max_tkn)
#                 if key in edges:
#                     if (edges[key]['p(token2|token)'] <= 0.1 and
#                             edges[key]['p(token|token2)'] <= 0.1):
#                         grp[tkn].append(tkn2)

#     def __get_all_ancestors(self, nodes, token, include_parents=False):
#         ancestors = []
#
#         for parent in nodes[token]['parents']:
#             ancestors.extend(self.__get_all_ancestors(nodes, parent, True))
#
#         if include_parents:
#             ancestors.extend(nodes[token]['parents'])
#
#         return ancestors

    def __get_major_alias(self, alias_graph, token):
        # print(alias_graph[token], token)
        if alias_graph[token] is None:
            return token
        else:
            return self.__get_major_alias(alias_graph, alias_graph[token])

    def __insert_nodes_and_edges(self, nodes, edges):
        with self._conn.cursor() as cur:
            # For nodes
            cur.execute('TRUNCATE TABLE token_node')
            vals = []
            len_nodes = len(nodes)
            for i in range(1, len_nodes + 1):
                _, v = nodes.popitem()
                vals.append("%s,'%s','%s','{%s}',%s,%s,%s,%s" % (
                    v['id'], v['token'], v['alias'], ','.join(v['parents']),
                    v['token_count'], v['row_count'], v['token_ratio'],
                    v['num_subsets']))

                if len(vals) >= self.__batch_size:
                    cur.execute('INSERT INTO token_node(id,token,alias,parents'
                                ',token_count,row_count,token_ratio,'
                                'num_subsets) VALUES(%s)' % '),('.join(vals))
                    vals = []
                    logger.info('%9s/%s nodes inserted in token_node.' %
                                (i, len_nodes))

            if len(vals) > 0:
                cur.execute('INSERT INTO token_node(id,token,alias,parents'
                            ',token_count,row_count,token_ratio,'
                            'num_subsets) VALUES(%s)' % '),('.join(vals))
                vals = []
                logger.info('%9s/%s nodes inserted in token_node.' %
                            (i, len_nodes))

            # For edges
            cur.execute('TRUNCATE TABLE token_edge')
            vals = []
            len_edges = len(edges)
            for i in range(1, len_edges + 1):
                _, v = edges.popitem()
                vals.append("%s,'%s','%s',%s,%s,%s" % (
                    v['id'], v['token'], v['token2'], v['p(token2|token)'],
                    v['p(token|token2)'], v['intersection_row_count']))

                if len(vals) >= self.__batch_size:
                    cur.execute('INSERT INTO token_edge(id,token,token2,'
                                '"p(token2|token)","p(token|token2)",'
                                'intersection_row_count) VALUES (%s)' %
                                '),('.join(vals))
                    vals = []
                    logger.info('%9s/%s edges inserted in token_edge.' %
                                (i, len_edges))

            if len(vals) > 0:
                cur.execute('INSERT INTO token_edge(id,token,token2,'
                            '"p(token2|token)","p(token|token2)",'
                            'intersection_row_count) VALUES (%s)' %
                            '),('.join(vals))
                vals = []
                logger.info('%9s/%s edges inserted in token_edge.' %
                            (i, len_edges))

    def __get_max_id(self, rows):
        if len(rows) == 0:
            return 0
        else:
            return max([v['id'] for v in rows.values()])
