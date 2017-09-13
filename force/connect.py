from . import credentials as cred
from .util import to_be_deprecated, handle_res_list
import requests
import os
import shutil
import json


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
        from .soql import SOQL
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

    @to_be_deprecated('Connection.search', 'SOSL.get_results')
    def search(self, term, robj=None, rfields=None, limit=0):
        from .soql import SOSL
        sosl = SOSL(
            self,
            terms=term,
            sobject=robj,
            returning_fields=rfields)
        return sosl.get_results()

    def req_get(self, url):
        req = self.ses.get(
            url,
            headers=self.req_headers(),
            proxies=self.conn_proxies)
        res = req.json()
        if isinstance(res, dict):
            return res
        else:
            handle_res_list(res, url)

    def format_payload(self, payload):
        bools = {k: v for k, v in payload.items() if isinstance(v, bool)}
        others = {k: v for k, v in payload.items() if not isinstance(v, bool)}
        for k, v in bools.items():
            others[k] = str(v).lower()
        return json.dumps(others)

    def req_post(self, url, data):
        """Posts into Force"""
        jdata = self.format_payload(data)
        post_headers = self.req_headers()
        post_headers['Content-Type'] = 'application/json'
        req = self.ses.post(
            url,
            headers=post_headers,
            proxies=self.conn_proxies,
            data=jdata)
        res = req.json()
        if isinstance(res, list):
            print(data)
            handle_res_list(res, url)
        return res

    def req_patch(self, url, data):
        """Patches into Force"""
        jdata = self.format_payload(data)
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

    @to_be_deprecated('Connection.query', 'SOQL.get_results')
    def query(self, sql, verbose=False):
        from .soql import SOQL
        soql = SOQL(self, sql=sql)
        return soql.get_results()


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
