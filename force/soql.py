import os
import json
from .connect import Connection


def _mod_ab_path():
    return os.path.abspath(__file__)


def _mod_dir():
    return os.path.split(_mod_ab_path())[0]


def _sq_dir():
    return os.path.join(_mod_dir(), 'stored_queries')


def stored_queries():
    ld = os.listdir(_sq_dir())
    ld = [x for x in ld if x.split('.')[-1] == 'json']
    rtn = {}
    for pos in ld:
        try:
            q = Query(pos)
            rtn[q.name_] = {'f': pos, 'q': q}
        except Exception as e:
            pass
    return rtn


class QueryBuilder():
    """ Accepts fields, Force Object, and filter text... returns SOQL """
    def __init__(self, force_obj, fields=['Id'], filters=None, limit=None):
        self.force_obj = force_obj
        self.fields = fields
        self.filters = filters
        self.limit = limit
        self.query = Query(self)

    def soql(self):
        return self.query.soql()


class Query():
    """ retrieves stored or creates new query """

    def __init__(self, param):
        self.tested = False
        if isinstance(param, QueryBuilder):
            self.from_builder(param)
        elif isinstance(param, str):
            self.from_filename(param)
        else:
            msg = 'Input Parameter must be a QueryBuilder object or filename.'
            raise RuntimeError(msg)

    def __str__(self):
        return self.soql()

    def from_builder(self, pobj):
        self.force_obj = pobj.force_obj
        self.fields = pobj.fields
        self.filters = pobj.filters
        self.limit = pobj.limit
        self.name_ = None

    def from_filename(self, fn):
        fn_text = os.path.join(_sq_dir(), fn)
        if not os.path.isfile(fn_text):
            msg = '%s not found in %s' % (fn, _sq_dir())
            raise RuntimeError(msg)
        with open(fn_text, 'r') as f:
            sd = json.load(f)
        self.force_obj = sd['force_obj']
        self.fields = sd['fields']
        self.filters = sd['filters']
        self.limit = sd['limit']
        self.tested = sd['tested']
        tname = fn.split('.')
        tname.pop(-1)
        self.name_ = '.'.join(tname)

    def soql(self):
        txt = 'SELECT %s FROM %s' % (
            ','.join(self.fields),
            self.force_obj)
        if self.filters:
            txt += ' WHERE %s' % " AND ".join(self.filters)
        if self.limit:
            txt += ' LIMIT %s' % self.limit
        return txt

    def to_dict(self):
        return {
            'force_obj': self.force_obj,
            'fields': self.fields,
            'filters': self.filters,
            'limit': self.limit,
            'tested': self.tested
        }

    def save_as(self, qname):
        fn = '%s.json' % qname
        fn_text = os.path.join(_sq_dir(), fn)
        if os.path.isfile(fn_text) and self.name_ is None:
            msg = '%s already exists. Overwrite (y/n)?: ' % qname
            ow = input(msg)
            if ow != 'y':
                return False
        if not self.tested:
            if not self.test_query()[0]:
                msg = 'Query Failed Self Test.'
                raise RuntimeError(msg)
                return False
        self.name_ = qname
        with open(fn_text, 'w') as f:
            json.dump(self.to_dict(), f, indent=3)
        return os.path.isfile(fn_text)

    def save(self):
        sname = self.name_ if self.name_ is not None else self.force_obj
        return self.save_as(sname)

    def test_query(self):
        real_limit = self.limit
        self.limit = '5'
        resp = 'test passed.'
        try:
            conn = Connection()
            rslt = conn.query(self.soql())
            self.tested = rslt is not None
        except Exception as e:
            resp = str(e)
            self.tested = False
        self.limit = real_limit
        return (self.tested, resp)
