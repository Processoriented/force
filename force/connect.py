from . import credentials as cred
from .util import flatten, format_search_terms
from .util import to_be_deprecated
from .soql import SOQL
import requests
import _thread as thread
import time
import os
import shutil
import json

stdoutmutex = thread.allocate_lock()
exitmutexes = [True] * 75


def create_local_creds():
    fp = os.path.split(__file__)
    cp = os.path.join(fp[0], 'credentials')
    lcfp = os.path.join(cp, 'local.py')
    if not os.path.exists(lcfp):
        shutil.copy2(os.path.join(cp, 'public.py'), lcfp)


def proxies():
    dflt = 'PITC-Zscaler-US-MilwaukeeZ.proxy.corporate.ge.com'
    return {
        'http': 'http://%s:9400' % dflt,
        'https': 'https://%s:9400' % dflt}


class Connection():
    """ creates connection to Force API and allows queries """

    def __init__(self, env='production'):
        self.env = env
        self.conn_proxies = None
        self.AUTH_URL = cred.AUTH_URL[env]
        self.AUTH_HEADERS = cred.AUTH_HEADERS
        self.AUTH_CREDS = cred.AUTH_CREDS[env]
        hascrd = []
        for key in self.AUTH_CREDS.keys():
            hascrd.append(
                (key == 'grant_type') or (
                    self.AUTH_CREDS[key] is not None))
        if False in hascrd:
            msg = [
                'Credentials need to be set up in local file.',
                'Local file should be at force/credentials/local.py.',
                'Populate all items currently set to "None".'
            ]
            create_local_creds()
            raise RuntimeError('\n'.join(msg))
        self.ses = requests.Session()
        self.auth = self.authorize()
        self.verbose = False

    def authorize(self):
        """ posts config data to Salesforce to get access token etc. """
        try:
            req = self.ses.post(
                self.AUTH_URL,
                self.AUTH_CREDS,
                self.AUTH_HEADERS,
                proxies=self.conn_proxies)
            auth = req.json()
            return auth
        except Exception as e:
            if self.conn_proxies is None:
                self.conn_proxies = proxies()
                return self.authorize()
            raise e

    def req_headers(self):
        """ formatted http headers for get requests """
        return {'Authorization': "Bearer " + self.auth['access_token']}

    @to_be_deprecated('Connection.qurl', 'SOQL._url')
    def qurl(self, sql):
        soql = SOQL(self, sql=sql)
        return soql._url()

    def search_pcl(self, term, robj, limit=0):
        """
        Checks if primary compact layout exists and returns
        search results with pcl fields
        """
        pcl_url = '%s/services/data/v39.0/sobjects/%s' % (
            self.auth['instance_url'], robj)
        pcl_url = '%s/describe/compactLayouts/primary' % pcl_url
        lfields = {'Id': 'Id', 'Name': 'Name'}
        try:
            pcl = self.req_get(pcl_url)
        except Exception as e:
            print("Exception trying to get pcl:\n(%s)" % str(e))

        # verify response
        check = [('is dict', isinstance(pcl, dict))]
        if check[-1][1]:
            check.append((
                'has fieldItems', 'fieldItems' in pcl.keys()))
            fis = pcl['fieldItems']
        if check[-1][1]:
            check.append(('fI is list', isinstance(fis, list)))
        if check[-1][1]:
            fids = [x for x in fis if isinstance(x, dict)]
            check.append(('fI count', len(fids) > 0))
        if check[-1][1]:
            fids = [x for x in fids if 'label' in x.keys()]
            fids = [x for x in fids if 'layoutComponents' in x.keys()]
            check.append(('fIs have labels', len(fids) > 0))
        if check[-1][1]:
            ficd = {x['label']: x['layoutComponents'][0] for x in fids}
            ficd = {k: v for k, v in ficd.items() if 'value' in v.keys()}
            check.append(('layoutComps have values', len(ficd.keys()) > 0))
        if check[-1][1]:
            lfields = {v['value']: k for k, v in ficd.items()}
        else:
            msg = "Unexpected server response for %s layout." % robj
            msg = "%s\n%s\n(%s)." % (msg, check[-1][0], str(pcl))
            print(msg)

        # extract layout fields from pcl
        if 'Id' not in lfields.keys():
            lfields['Id'] = 'Id'
        rfields = [k for k in lfields.keys()]

        # run search
        rslt = self.search(term, robj, rfields, limit)
        rslts = [
            {k: '' if k not in x.keys() else x[k]
                for k in lfields.keys()} for x in rslt]

        # return with layout
        return {
            'labels': lfields,
            'rslts': rslts}

    def search(self, term, robj=None, rfields=None, limit=0):
        """
        Takes search term, and optional return object robj, return fields
        rfields, and limit integer to give url for search.
        """
        if not isinstance(term, list):
            term = [term]
        cterm = format_search_terms(term)
        base = '%s/services/data/v39.0/search?q=FIND+{%s}+IN+ALL+FIELDS' % (
            self.auth['instance_url'], cterm)
        if robj is not None:
            cfields = "(Id,Name)"
            if isinstance(rfields, list):
                cfields = "(%s)" % ",".join(rfields)
            elif isinstance(rfields, str):
                cfields = "(%s)" % ",".join(
                    [x.strip() for x in rfields.split(',')])
            base = '%s+RETURNING+%s+%s' % (base, robj, cfields)
        if int(limit) > 0:
            base += "+LIMIT+%d" % int(limit)
        url = "+".join(base.split(' '))
        res = self.req_get(url)
        if 'searchRecords' not in res.keys():
            self.recs = None
        else:
            self.recs = [flatten(x) for x in res['searchRecords']]
        return self.recs

    def handle_res_list(self, res):
        unknown = 'Unknown Error in API transaction: [%s]' % str(res)
        if not isinstance(res[0], dict):
            raise RuntimeError(unknown)
        errorCode = res[0].get('errorCode', None)
        message = res[0].get('message', None)
        fields = res[0].get('fields', [])
        if errorCode is not None and message is not None:
            msg_append = '(Fields: [%s])' % ', '.join(fields)
            msg_append = '' if len(fields) == 0 else msg_append
            raise RuntimeError('%s: %s%s' % (errorCode, message, msg_append))
        raise RuntimeError(unknown)
        return

    def req_get(self, url):
        req = self.ses.get(
            url,
            headers=self.req_headers(),
            proxies=self.conn_proxies)
        res = req.json()
        if isinstance(res, dict):
            return res
        else:
            self.handle_res_list(res)

    def req_post(self, url, data):
        """Posts into Force"""
        jdata = json.dumps(data)
        post_headers = self.req_headers()
        post_headers['Content-Type'] = 'application/json'
        req = self.ses.post(
            url,
            headers=post_headers,
            proxies=self.conn_proxies,
            data=jdata)
        res = req.json()
        if isinstance(res, list):
            self.handle_res_list(res)
        return res

    def req_patch(self, url, data):
        """Patches into Force"""
        jdata = json.dumps(data)
        post_headers = self.req_headers()
        post_headers['Content-Type'] = 'application/json'
        req = self.ses.patch(
            url,
            headers=post_headers,
            proxies=self.conn_proxies,
            data=jdata)
        res = req
        return res

    def msg_print(self, msg, always_print=False):
        if self.verbose or always_print:
            print(msg)

    def query(self, sql, verbose=False):
        """ runs query against force api. """
        self.verbose = verbose
        self.msg_print("initializing query.")
        res = self.req_get(self.qurl(sql))
        done = res['done']
        self.recs = [flatten(x) for x in res['records']]
        totalSize = res['totalSize'] * 1
        if not done:
            self.handle_additional(totalSize, res['nextRecordsUrl'])
        self.msg_print('Retrieved %d of %d records.' % (
            len(self.recs),
            totalSize), verbose)
        return self.recs

    def handle_additional(self, totalSize, nrUrl):
        """
        if force result specifies more records, spawn threads to add them.
        """
        nrUrlBase = nrUrl.split('-')
        next_Num = nrUrlBase.pop() * 1
        ourls = []
        idx = next_Num
        while int(idx) < int(totalSize):
            ourls.append("%s-%s" % ('-'.join(nrUrlBase), idx))
            idx = str(int(next_Num) + int(idx))
        while len(ourls) > 0:
            while exitmutexes.count(True) == 0:
                time.sleep(2)
            nurl = ourls.pop(0)
            th_id = exitmutexes.index(True)
            exitmutexes[th_id] = False
            thread.start_new_thread(self.get_next, (nurl, th_id))
            msg = 'retrieving records starting at %s.' % nurl.split('-').pop()
            self.msg_print(msg)
        while exitmutexes.count(False) > 0:
            time.sleep(5)

    def get_next(self, url, thid):
        res = self.req_get(self.auth['instance_url'] + url)
        self.recs.extend([flatten(x) for x in res['records']])
        exitmutexes[thid] = True


class ConnTrainusers(Connection):
    """sets connection to trainusers"""
    def __init__(self):
        super(ConnTrainusers, self).__init__('trainusers')


def tsql():
    tsql = """
SELECT Id
FROM SVMXC__Installed_Product__c
WHERE RecordTypeId = '01280000000M0oXAAS'
"""
    return " ".join(tsql.split('\n')).strip()


if __name__ == '__main__':
    conn = Connection()
    print(len(conn.query(tsql())))
