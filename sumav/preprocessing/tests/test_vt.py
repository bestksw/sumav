''
# Default packages
import os
import sys
import logging
from pprint import pprint

# 3rd-party packages

# Internal packages
import sumav.conf as conf
from sumav.preprocessing.base import PreprocessingBase
from sumav.preprocessing.from_vt_api_v2 import FromVirusTotalAPIv2
from sumav.preprocessing.from_vt_filefeed import FromVirusTotalFileFeed

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)


class TestVT:
    @classmethod
    def setup_class(cls):
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)

        conf.psql_conf['database'] = 'sumav_test'
        pprint(conf.get_conf())

        base = PreprocessingBase(**conf.psql_conf)
        base.truncate_all()
        base.commit()
        base.close()

    def setup(self):
        self.__here = os.path.abspath(os.path.dirname(__file__)) + '/'

    def test_vt_api_v2(self):
        pprint(conf.get_conf())
        from_vtapi = FromVirusTotalAPIv2(**conf.psql_conf)
        init_cnt = from_vtapi.detection_count()
        from_vtapi.convert(self.__here + 'part_malheurReference_lb.json',
                           self.__here + 'part_change_all_gt.tsv')
        after_cnt = from_vtapi.detection_count()
        from_vtapi.close()

        print('Count of detection table: %s -> %s' % (init_cnt, after_cnt))
        assert after_cnt > init_cnt

    def test_vt_filefeed(self):
        from_vtfeed = FromVirusTotalFileFeed(**conf.psql_conf)
        init_cnt = from_vtfeed.detection_count()
        from_vtfeed.convert(self.__here + 'file-20200526T0831.tar.bz2')
        after_cnt = from_vtfeed.detection_count()
        from_vtfeed.close()
        
        print('Count of detection table: %s -> %s' % (init_cnt, after_cnt))
        assert after_cnt > init_cnt
