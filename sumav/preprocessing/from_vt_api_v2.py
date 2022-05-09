'''
VT RDB helper
'''
# Default packages
import os
import csv
import json
import logging
from traceback import format_exc

# 3rd-party packages
import requests
from requests.exceptions import RequestException

# Internal packages
import sumav.conf as conf
from sumav.preprocessing.base import PreprocessingBase

logger = logging.getLogger(__name__)


class FromVirusTotalAPIv2(PreprocessingBase):
    _bytea_cols = ['md5', 'sha1', 'sha256']

    def convert(self, src_path, gt_path=None, file_ext=None):
        if file_ext is None:
            file_ext = os.path.splitext(src_path)[1][1:]

        gt = {}
        if gt_path is not None:
            with open(gt_path) as f:
                reader = csv.reader(f, delimiter='\t')
                for row in reader:
                    gt[row[0]] = row[1].lower()

        if file_ext == 'json':
            with open(src_path) as f:
                lines = f.readlines()
                for i, line in enumerate(lines, 1):
                    item = json.loads(line)
                    hash_ = self.__insert_item(item, gt)
                    print('%5s/%s %s' % (i, len(lines), hash_))

        elif file_ext == 'csv':
            with open(src_path) as f:
                num_lines = len(f.readlines()) - 1
                f.seek(0)
                for i, item in enumerate(csv.DictReader(f), 1):
                    hash_ = self.__insert_item(item, gt)
                    print('%5s/%s %s' % (i, num_lines, hash_))

    def __insert_item(self, item, gt, vt_apikey=conf.vt_apikey):
        hashtype = None
        if hashtype is not None:
            pass
        elif 'sha256' in item:
            hashtype = 'sha256'
        elif 'md5' in item:
            hashtype = 'md5'
        elif 'sha1' in item:
            hashtype = 'sha1'

        report = self.__get_vt_report(item[hashtype], vt_apikey)

        # report['sha1'] = item['sha1']
        self.__insert_row(report, gt)
        return item[hashtype]

    def __insert_row(self, row, gt):
        row['submission.date'] = row.pop('first_seen')
        if gt:
            row['ground_truth'] = gt.get(row['sha1'])
            if row['ground_truth'] is None:
                row['ground_truth'] = 'exp'
                logger.error('No ground truth (sha1:%s sha256:%s)' %
                             (row['sha1'], row['sha256']))

        sql, vals = self._make_insert_sql([row])
        with self._conn.cursor() as cur:
            cur.execute(sql, vals)
        self._conn.commit()

    def __get_vt_report(self, hash_, vt_apikey=conf.vt_apikey):
        '''Search files with hash.

        :param str hash\_: A hash of file
        :return: If 404 error (which means no report exists) return None
            else dict form of a report
        :rtype: None or dict
        :raises requests.exceptions.RequestException:
        '''
        if not hash_:
            raise Exception('Given hash is empty.')
        if vt_apikey is None:
            raise Exception('Please set VT_APIKEY environment variable.')

        vt_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': vt_apikey, 'resource': hash_, 'allinfo': 1}
        out = self.__request(vt_report_url, params, jsonfy=True)

        if 'scans' in out:
            for _, v in out['scans'].items():
                del v['update'], v['version'], v['detected']

        return out

    def __request(self, url, params=None, data=None, jsonfy=False):
        try:
            if data is None:  # GET
                resp = requests.get(url, params=params)
            elif data is not None:  # POST
                resp = requests.post(url, data=data)

            resp.raise_for_status()
            if jsonfy:
                return resp.json()
            else:
                return resp.content

        except requests.exceptions.HTTPError:
            if resp.status_code == 404:
                # File not found
                logger.info('Not found in URL: %s' % url)
                return None
            else:
                # Server Error
                raise

        # socket.gaierror, urllib3.exceptions.HTTPError
        # requests.exceptions.ConnectionError
        except RequestException:
            # Internet connection problem
            logger.error('%s\n%s' % (url, format_exc()))
            raise
