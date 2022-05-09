'''
Implementation of command line interface
'''
# Default packages
import os
import sys
import json
import logging
import argparse
from pprint import pprint

# Internal packages
import sumav.conf as conf
from sumav import (SumavGraphBuilder, SumavGraphManager, SumavGraphSearcher,
                   FromVirusTotalFileFeed, FromVirusTotalAPIv2)
from sumav.version import __version__

logger = logging.getLogger(__name__)


def console_main(argv=None):
    def eval_list(x):
        listi = json.loads(x)
        assert isinstance(listi, list)
        return listi

    eg = '''examples:
$ sumav run select '["PUP/Win32.Dealply.C3316715", "Win32:DealPly-AJ [Adw]"\
, "a variant of Win32/DealPly.RC potentially unwanted", null]'
'''
    psr = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True, epilog=eg)
    psr.add_argument(
        '-l', '--logging_level', default='i',
        choices=['n', 'c', 'e', 'w', 'i', 'd'],
        help='n:none, c:critical, e:error, w:warn, i:info, d:debug')
    psr.add_argument('-v', '--version', action='version',
                     version=__version__)
    psr.add_argument('-s', '--show-config', action='store_true',
                     help='show configs came from environment variables. '
                          '(refer to %s)' % conf.__file__)

    subpsr_cm = psr.add_subparsers(dest='command', help='command to run')

    psr_cm_bu = subpsr_cm.add_parser('build')
    psr_cm_bu.add_argument('-p', '--preprocess-only', action='store_true')
    subpsr_cm_bu_da = psr_cm_bu.add_subparsers(dest='datatype',
                                               help='preprocess data from')

    psr_cm_im_me_vt = subpsr_cm_bu_da.add_parser('vt', help='virustotal')
    psr_cm_im_me_vt.add_argument('filefeed_path')
    subpsr_cm_bu_da.add_parser('none', help='skip preprocess')

    psr_cm_mi = subpsr_cm.add_parser('migrate')
    subpsr_cm_mi_ac = psr_cm_mi.add_subparsers(dest='action',
                                               help='command to run')

    subpsr_cm_mi_ac.add_parser('dump_graph')

    psr_cm_mi_ac_pu = subpsr_cm_mi_ac.add_parser('pull_dumped_graph')
    psr_cm_mi_ac_pu.add_argument('-H', '--host', required=True)
    psr_cm_mi_ac_pu.add_argument('-P', '--port', type=int, default=5432)
    psr_cm_mi_ac_pu.add_argument('-u', '--user', default='postgres')
    psr_cm_mi_ac_pu.add_argument('-p', '--password', required=True)
    psr_cm_mi_ac_pu.add_argument('-g', '--graph-name')

    psr_cm_mi_ac_gn = subpsr_cm_mi_ac.add_parser('get_new_dumped_graph_name')
    psr_cm_mi_ac_gn.add_argument('-H', '--host', required=True)
    psr_cm_mi_ac_gn.add_argument('-P', '--port', type=int, default=5432)
    psr_cm_mi_ac_gn.add_argument('-u', '--user', default='postgres')
    psr_cm_mi_ac_gn.add_argument('-p', '--password', required=True)

    psr_cm_mi_ac_gd = subpsr_cm_mi_ac.add_parser('get_dumped_graph_names')
    psr_cm_mi_ac_gd.add_argument('-H', '--host', default='127.0.0.1')
    psr_cm_mi_ac_gd.add_argument('-P', '--port', type=int, default=5432)
    psr_cm_mi_ac_gd.add_argument('-u', '--user', default='postgres')
    psr_cm_mi_ac_gd.add_argument('-p', '--password', default='')

    psr_cm_ru = subpsr_cm.add_parser('run')
    subpsr_cm_ru_me = psr_cm_ru.add_subparsers(dest='method',
                                               help='query methods')

    psr_cm_ru_me_se = subpsr_cm_ru_me.add_parser('select')
    psr_cm_ru_me_se.add_argument('av_labels', type=eval_list, nargs=1)
    psr_cm_ru_me_se.add_argument(
        '-n', '--top-n', type=int,
        help='if set, n length list of tuple (token,score) will be returned.')
    psr_cm_ru_me_se.add_argument(
        '-w', '--weight-param', type=int, default=4.1,
        help=('smaller value makes affect the result more by AV labes of'
              'the given file. (default: 4.1, recommand val>=2)'))
    psr_cm_ru_me_se.add_argument(
        '-g', '--general-param', type=int, default=225,
        help=('smaller value increases the possibility of appearance of '
              'general tokens more. (default: 225, recommand val>=36)'))

    psr_cm_ru_me_co = subpsr_cm_ru_me.add_parser('compare')
    psr_cm_ru_me_co.add_argument('tokens', nargs=2)

    psr_cm_ru_me_si = subpsr_cm_ru_me.add_parser('similar')
    psr_cm_ru_me_si.add_argument('token', nargs=1)

    ns = psr.parse_args(argv)
    cmd_args = vars(ns)

    logging_level = cmd_args.pop('logging_level')
    if logging_level.startswith('n'):
        pass
    elif logging_level.startswith('c'):
        logging.getLogger().handlers = []
        logging.basicConfig(level=logging.CRITICAL, stream=sys.stdout)
    elif logging_level.startswith('e'):
        logging.getLogger().handlers = []
        logging.basicConfig(level=logging.ERROR, stream=sys.stdout)
    elif logging_level.startswith('w'):
        logging.getLogger().handlers = []
        logging.basicConfig(level=logging.WARN, stream=sys.stdout)
    elif logging_level.startswith('d'):
        logging.getLogger().handlers = []
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    else:
        logging.getLogger().handlers = []
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    if cmd_args['show_config']:
        pprint(conf.get_conf())
        return

    command = cmd_args.pop('command')
    if command == 'build':
        # Preprocess data
        if cmd_args['datatype'] == 'vt':  # came from VirusTotal
            from_vt = FromVirusTotalFileFeed(**conf.psql_conf)
            from_vt.convert(cmd_args['filefeed_path'])
            from_vt.close()

        if cmd_args['preprocess_only'] and cmd_args['datatype'] is not None:
            return

        if cmd_args['datatype'] is None:
            psr_cm_bu.print_help()
        else:
            # Build graph
            builder = SumavGraphBuilder(**conf.psql_conf)
            builder.build_graph()
            builder.close()

        return

    elif command == 'migrate':
        try:
            manager = SumavGraphManager(**conf.psql_conf)
            kwargs = {k: v for k, v in cmd_args.items()
                      if k in ['user', 'password', 'host', 'port']}

            if cmd_args['action'] == 'dump_graph':
                dbname = manager.__dump_remote_sumav_graph()
                if dbname:
                    print('%s database generaged.' % dbname)

            elif cmd_args['action'] == 'pull_dumped_graph':
                kwargs['graph_name'] = cmd_args['graph_name']
                dbname = manager.dump_sumav_graph(**kwargs)
                print('%s database pulled.' % dbname)

            elif cmd_args['action'] == 'get_new_dumped_graph_name':
                pprint(manager.get_new_dumped_graph_name(**kwargs))

            elif cmd_args['action'] == 'get_dumped_graph_names':
                pprint(manager.pull_sumav_graph_lists(**kwargs))

            else:
                psr_cm_mi.print_help()

        finally:
            manager.close()
        return

    elif command == 'run':
        try:
            searcher = SumavGraphSearcher(**conf.psql_conf)
            if cmd_args['method'] == 'select':
                kwargs = {k: v for k, v in cmd_args.items()
                          if k in ['top_n', 'weight-param', 'general-param']}
                out = searcher.get_representative_token(
                    av_labels=cmd_args['av_labels'][0], **kwargs)
                if out:
                    print(out)
                else:
                    print('Sumav could not select representation tokens.')

            elif cmd_args['method'] == 'compare':
                out = searcher.compare_tokens(*cmd_args['tokens'])
                if out:
                    pprint(out)
                else:
                    print('No match relations were found')

            elif cmd_args['method'] == 'similar':
                out = searcher.get_related_tokens(cmd_args['token'][0])
                if out:
                    pprint(out)
                else:
                    print('No match tokens were found')
            else:
                psr_cm_ru.print_help()

        finally:
            searcher.close()
        return

    psr.print_help()


# Examples of how to use it
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    pprint(conf.get_conf())
    here = os.path.abspath(os.path.dirname(__file__)) + '/'

    from_vtapi = FromVirusTotalAPIv2(**conf.psql_conf)
    # processing_test = here + 'preprocessing/tests/%s'
    # from_vtapi.convert(processing_test % 'malheurReference_lb.json',
    #                    processing_test % 'change_all_gt.tsv')
    from_vtapi.close()

    from_vtfeed = FromVirusTotalFileFeed(**conf.psql_conf)
#     from_vtfeed.convert('/srv/vt_feed_raw_data/')
    from_vtfeed.close()

    builder = SumavGraphBuilder(**conf.psql_conf)
#     builder.build_graph()
    builder.close()

    manager = SumavGraphManager(**conf.psql_conf)
#     print(manager.dump_graph())
#     print(manager.pull_dumped_graph('sumav', 'sumav1234!!', '172.31.10.10',
#                                     graph_name='sumav_dev_201231-210331'))
#     print(manager.get_new_dumped_graph_name('user', 'password',
#                                             '192.168.236.10'))
#     print(manager.get_dumped_graph_names())
#     print(manager.load_dumped_graph())
#     print(manager.get_submission_date_range())
    manager.close()

    searcher = SumavGraphSearcher(**conf.psql_conf)
    kwparams = {'weight_param': 4.1, 'general_param': 225}

#     dn = ['PUP/Win32.Dealply.C3316715', 'Win32:DealPly-AJ [Adw]',
#           'a variant of Win32/DealPly.RC potentially unwanted', None,
#           'DealPly Updater (PUA)', None, None]
#     print(searcher.get_representative_token(av_labels=dn, **kwparams))

#     s2 = '62873c1e68161a44093d54ddc08db86132fd88c2f5af5f40f014acfe7b141511'
#     rows = list(searcher.get_detection_rows(database='sumav_exp', sha256=s2))
#     print(searcher.get_representative_token(
#         tokens=rows[0]['tokens'], top_n=5, **kwparams))
#     pprint(searcher.get_graph(sha256=s2))

#     print(searcher.get_related_tokens('adrotator'))
#     print(searcher.compare_tokens('casino', 'casonline'))

#     rows = searcher.get_detection_rows(database='sumav_exp2')
#     searcher.update_sumav_results(rows=rows)
#     pprint(searcher.get_metrics())

#     rows = searcher.get_detection_rows(database='sumav_exp2')
#     results = searcher.get_sumav_results(rows, top_n=None, **kwparams)
#     pprint(searcher.get_metrics(results))
    searcher.close()
