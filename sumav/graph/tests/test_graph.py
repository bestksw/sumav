''
# Default packages
import os
import sys
import logging
from pprint import pprint

# 3rd-party packages
import pytest

# Internal packages
import sumav.conf as conf
from sumav import (SumavGraphBuilder, SumavGraphManager, SumavGraphSearcher,
                   FromVirusTotalFileFeed)

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)


class TestGraphBuilder:
    @classmethod
    def setup_class(cls):
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

        conf.psql_conf['database'] = 'sumav_test'
        pprint(conf.get_conf())

        here = os.path.abspath(os.path.dirname(__file__)) + '/'
        preproc_test_path = here + '../../preprocessing/tests/'
        
        from_vtfeed = FromVirusTotalFileFeed(**conf.psql_conf)
        from_vtfeed.truncate_all()
        from_vtfeed.convert(preproc_test_path + 'file-20200526T0831.tar.bz2')
        from_vtfeed.close()

    def test_builder(self):
        builder = SumavGraphBuilder(**conf.psql_conf)
        builder.build_graph()
        graph_size = builder.get_graph_size()
        builder.close()

        print(graph_size)
        assert graph_size['node_size'] > 0
        assert graph_size['edge_size'] > 0


class TestGraphManager:
    @classmethod
    def setup_class(cls):
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

        conf.psql_conf['database'] = 'sumav_test'
        pprint(conf.get_conf())

        here = os.path.abspath(os.path.dirname(__file__)) + '/'
        preproc_test_path = here + '../../preprocessing/tests/'
        
        from_vtfeed = FromVirusTotalFileFeed(**conf.psql_conf)
        from_vtfeed.truncate_all()
        from_vtfeed.convert(preproc_test_path + 'file-20200526T0831.tar.bz2')
        from_vtfeed.close()

        builder = SumavGraphBuilder(**conf.psql_conf)
        builder.build_graph()
        builder.close()

        # Remove dumped sumav graph in test
        manager = SumavGraphManager(**conf.psql_conf)
        graph_list = manager.get_sumav_graph_list(remote=False)
        for graph_name in graph_list:
            if graph_name.startswith('sumav_test_'):
                manager.remove_sumav_graph(graph_name, remote=False)

    def setup(self):
        self.__manager = SumavGraphManager(**conf.psql_conf)

    def teardown(self):
        self.__manager.close()

    def test_pull_sumav_graph(self):
        # Test get_sumav_graph_list
        remote_graph_list = self.__manager.get_sumav_graph_list(remote=True)
        print('Sumav graph list in remote: %s' % remote_graph_list)
        assert 'sumav_test' in remote_graph_list

        # Test dump_sumav_graph
        graph_name = self.__manager.dump_sumav_graph('sumav_test', remote=True)
        print('pulled Sumav graph name: %s' % graph_name)
        local_graph_list = self.__manager.get_sumav_graph_list(remote=False)
        dumped_graph_cnt = 0
        for graph_name in local_graph_list:
            if graph_name.startswith('sumav_test_'):
                dumped_graph_cnt += 1

        assert dumped_graph_cnt == 1

class TestGraphSearcher:
    @classmethod
    def setup_class(cls):
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

        conf.psql_conf['database'] = 'sumav_test'
        pprint(conf.get_conf())

        here = os.path.abspath(os.path.dirname(__file__)) + '/'
        preproc_test_path = here + '../../preprocessing/tests/'
        
        from_vtfeed = FromVirusTotalFileFeed(**conf.psql_conf)
        from_vtfeed.truncate_all()
        from_vtfeed.convert(preproc_test_path + 'file-20200526T0831.tar.bz2')
        from_vtfeed.close()

        builder = SumavGraphBuilder(**conf.psql_conf)
        builder.build_graph()
        builder.close()

    def setup(self):
        self.__searcher = SumavGraphSearcher(**conf.psql_conf)
        self.__kwparams = {'weight_param': 4.1, 'general_param': 225}

    def teardown(self):
        self.__searcher.close()

    def test_compare_tokens(self):
        result = self.__searcher.compare_tokens('win32', 'ransom')
        pprint(result)
        assert result['relation'] == '⊃'
        assert result['p(token|token2)'] > 0.99
        assert result['p(token2|token)'] > 0.5

    def test_get_related_tokens(self):
        result = self.__searcher.get_related_tokens('ransom')
        pprint(result)
        assert 'winlock' in result['subsets']
        assert 'win32' in result['supersets']

    def test_get_representative_token(self):
        dn = [
            'Win32/Nabucur', 'Win32:VirLock', 'Win32.Virus.Virlock.a',
            'Packed.Win32.Graybird.B@5hgpd5', 'W32/S-27bc0672!Eldorado',
            'Win32.VirLock.1', 'Generic.mg.a24374c791796544', None]
        result = self.__searcher.get_representative_token(
            av_labels=dn, top_n=3, **self.__kwparams)
        pprint(result)

        assert result[0][0] == 'virlock'

    def test_get_metrics(self):
        # load detections
        rows = list(self.__searcher.get_detection_rows())
        print('\nget_detection_rows():')
        pprint({k : v for k, v in rows[0].items() if k != 'tokens'})

        assert len(rows) > 0

        # process to get sumav results
        results = list(
            self.__searcher.get_sumav_results(rows, **self.__kwparams))
        print('\nget_sumav_results():')
        pprint(results[0])

        assert len(results) == len(rows)
        assert max([r['sumav_label'] is not None for r in results]) == True

        # update the sumav results
        self.__searcher.update_sumav_results(rows=results)
        row = next(self.__searcher.get_detection_rows())
        print('\nget_detection_rows() after update_sumav_results():')
        pprint({k : v for k, v in row.items() if k != 'tokens'})

        assert row['sumav_label'] is not None

        # get metrics from results
        metrics = self.__searcher.get_metrics(results)
        print('\nget_metrics():')
        pprint(metrics)

        assert metrics['fmeasure'] > 0
        assert metrics['precision'] > 0
        assert metrics['recall'] > 0

    def test_get_graph(self):
        s2='0173600a3b4418c1120a34c924b8bf371d663999c8ae1c2fa82f954d5c800463'
        graph = self.__searcher.get_graph(sha256=s2)
        pprint(graph, depth=2, compact=True)
        assert len(graph) > 0
