import os
import json
import _thread as thread
import time
from .connect import Connection
from .util import flatten, first_instance, format_search_terms
from .util import to_be_deprecated


stdoutmutex = thread.allocate_lock()
exitmutexes = [True] * 75


def _mod_ab_path():
    return os.path.abspath(__file__)


def _mod_dir():
    return os.path.split(_mod_ab_path())[0]


def _sq_dir():
    return os.path.join(_mod_dir(), 'stored_queries')


def parse_sql(sql):
    sql_keywords = ['SELECT', 'FROM', 'WHERE', 'LIMIT']
    unsupported = ['INNER', 'OUTER', 'JOIN', 'GROUP', 'ORDER']
    pieces = sql.split(' ')
    if len([x for x in pieces if x.upper() in unsupported]) > 0:
        raise_parse_error(sql)
    if pieces[0].upper() != sql_keywords[0]:
        raise_parse_error(sql)
    parts = {}
    next_kw = sql_keywords.pop(0)
    for i in range(len(pieces)):
        if pieces[i].upper() == next_kw:
            this_kw = pieces[i].upper()
            parts[this_kw] = []
            next_kw = sql_keywords.pop(0) if len(sql_keywords) > 0 else ' '
        elif pieces[i].upper() in sql_keywords[1:]:
            raise_parse_error(sql)
        else:
            parts[this_kw].append(pieces[i])
    fields = ' '.join(parts['SELECT']).strip().split(',')
    fields = [x.strip() for x in fields]
    sobject = [x.strip() for x in parts['FROM']]
    if len(sobject) != 1:
        raise_parse_error(sql)
    sobject = sobject[0]
    filters = None
    if 'WHERE' in parts.keys():
        filters = ' '.join(parts['WHERE']).strip()
    limit = None
    if 'LIMIT' in parts.keys():
        limit = ' '.join(parts['LIMIT']).strip()
        try:
            limit = int(limit)
        except Exception as e:
            raise_parse_error(sql)
    rtn = {
        'fields': fields,
        'sobject': sobject,
        'filters': filters,
        'limit': limit}
    return {k: v for k, v in rtn.items() if v is not None}


def raise_parse_error(sql):
    msg = 'Unable to parse SQL:\n%s\n' % sql
    raise RuntimeError(msg)


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
    def __init__(self, *args, **kwargs):
        """
        Builds a Stored Query Object
        Args/KeyWord Args:
            force_obj = SalesForce Sobject API Name
            fields = list of Fields to include
            filters = list of filters to include
            limit = integer limit for query
        enter args in this order for positional, or as keywords
        """
        self.fields = ['Id']
        self.filters = None
        self.limit = None
        positionals = ['force_obj', 'fields', 'filters', 'limit']
        for i in range(len(args)):
            setattr(self, positionals[i], args[i])
        for k, v in kwargs.items():
            setattr(self, k, v)
        if not hasattr(self, 'force_obj'):
            raise RuntimeError('Missing SalesForce Object "force_obj"')
        self.query = StoredQuery(self)

    def soql(self):
        return self.query.soql()


class StoredQuery():
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
        conn = getattr(self, 'conn', Connection())
        limit = 0 if self.limit is None else self.limit
        query_obj = SOQL(
            conn,
            fields=self.fields,
            sobject=self.force_obj,
            filters=self.filters,
            limit=limit)
        return query_obj._sql()

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


class Query(StoredQuery):
    @to_be_deprecated('Query class', 'StoredQuery class')
    def __init__(self, param):
        super(Query, self).__init__(param)


class SOQL():
    def __init__(self, connection, **kwargs):
        """
        Creates a SOQL query for SalesForce and gets results
        Accepts the following KeyWord Arguments:
            sobject: SalesForce Object to query
            fields: List of fields to query
            filters: List of QueryFilter objects for where clause
            filter_bool: Should top level filters be AND or OR?
            limit: limit of records to return
        """
        self.conn = connection
        if 'sql' in kwargs.keys():
            parsed = parse_sql(kwargs['sql'])
        else:
            parsed = kwargs
        self.fields = parsed.get('fields', ['Id'])
        self.sobject = parsed.get('sobject', None)
        filters = parsed.get('filters', [])
        self.filters = self._make_filters(filters)
        self.filter_bool = parsed.get('filter_bool', 'AND')
        self.limit = parsed.get('limit', 0)

    def _make_filters(self, given):
        """handles given filters and creates filter objects"""
        if isinstance(given, list):
            return [self._make_filter(x) for x in given]
        return [self._make_filter(given)]

    def _make_filter(self, given):
        """makes individual filters"""
        if isinstance(given, QueryFilter):
            return given
        return QueryFilter(given)

    def append_filter(self, given):
        """Appends Additional Filters"""
        new_filter = self._make_filter(given)
        self.filters.append(new_filter)

    def _sql(self):
        """Makes url safe sql text"""
        text = ['SELECT %s' % ','.join(self.fields)]
        text.append('FROM %s' % self.sobject)
        where_bool = ' %s ' % self.filter_bool.upper()
        text.append(
            'WHERE %s' % where_bool.join(
                [str(x) for x in self.filters]))
        if self.limit > 0:
            text.append('LIMIT %d' % self.limit)
        return ' '.join(text)

    def _url(self):
        """Makes URL for query"""
        instance_url = self.conn.auth['instance_url']
        base = '%s/services/data/v39.0/query?q=' % instance_url
        query_text = '+'.join(self._sql().split(' '))
        return '%s%s' % (base, query_text)

    def get_results(self):
        return QueryResult(self).records

    @to_be_deprecated('SOQL.results', 'SOQL.get_results')
    def results(self):
        return self.get_results()


class QueryResult():
    def __init__(self, query_):
        self.query_ = query_
        self._rec_keys = ['searchRecords', 'records']
        response = query_.conn.req_get(query_._url())
        for key, value in response.items():
            attr_ = 'raw_records' if key in self._rec_keys else key
            setattr(self, attr_, value)
        self.parse_results()

    def parse_results(self):
        if hasattr(self, 'raw_records'):
            self.read_records()
        self.get_additional()

    def read_records(self, to_read=None):
        to_read = self.raw_records if to_read is None else to_read
        flat = [flatten(x) for x in to_read]
        filtered = [{
            k: v for k, v in x.items() if k in self.query_.fields}
            for x in flat]
        self.records = getattr(self, 'records', []).extend(filtered)

    def get_additional(self):
        if not self.has_additional():
            return
        if not self.make_other_urls():
            return
        if not self.request_others():
            print('Issue while trying to get additional records')
            return

    def has_additional(self):
        null_ = [None, '']
        size = len(getattr(self, 'records', []))
        more = [
            getattr(self, 'nextRecordsUrl', None) not in null_,
            getattr(self, 'done', True) is not True,
            getattr(self, 'totalSize', size) > size]
        return sum(more) == 3

    def make_other_urls(self):
        split_url = self.nextRecordsUrl.split('-')
        next_num = int(split_url.pop())
        idx = next_num
        while idx < int(self.totalSize):
            self.other_urls = getattr(
                self, 'other_urls', []).append(
                '%s-%s' % ('-'.join(split_url), idx))
            idx += next_num
        self.other_urls = list(set(self.other_urls))
        return len(self.other_urls) > 0

    def request_others(self):
        while len(self.other_urls) > 0:
            while exitmutexes.count(True) == 0:
                time.sleep(2)
            url = self.other_urls.pop(0)
            thread_id = exitmutexes.index(True)
            exitmutexes[thread_id] = False
            thread.start_new_thread(self.get_next, (url, thread_id))
        while exitmutexes.count(False) > 0:
            time.sleep(5)
        return len(self.other_urls) == 0

    def get_next(self, url, thread_id):
        response = self.query_.conn.req_get(url)
        rec_key = [x for x in response.keys() if x in self._rec_keys][0]
        self.read_records(response[rec_key])
        exitmutexes[thread_id] = True


class QueryFilter():
    def __init__(self, text):
        self.tokens = []
        self.boolean = ' AND '
        self._parse_text(text)

    def _parse_text(self, given):
        first_and = first_instance(given, ' AND ')
        first_or = first_instance(given, ' OR ')
        compare = first_and - first_or
        if compare == 0:
            self.tokens = [QueryToken(given)]
            return
        if compare > 0:
            self.boolean = ' OR '
        self.tokens.extend(
            [QueryFilter(x) for x in given.split(self.boolean)])

    def __str__(self):
        return self.boolean.join([str(x) for x in self.tokens])


class QueryToken():
    def __init__(self, text):
        self.field = ''
        self.operator = ''
        self.value = ''
        self._parse_text(text)

    def _parse_text(self, given):
        operators = [
            '=', '!=', '>', '<', '>=', '<=', ' IN ', ' NOT IN ',
            ' LIKE ', ' NOT LIKE ']
        positions = {x: first_instance(given, x) for x in operators}
        min_pos = min([v for k, v in positions.items()])
        if min_pos == len(given):
            raise RuntimeError('No operator found in text: %s' % given)
        self.operator = [k for k, v in positions.items() if v == min_pos][0]
        self.field = given[:min_pos].strip()
        val_start = min_pos + len(self.operator)
        self.value = given[val_start:].strip()

    def __str__(self):
        return ''.join([self.field, self.operator, self.value])


class SOSL():
    def __init__(self, connection, **kwargs):
        """
        Creates an SOSL search query to run against given connection
        Accepts the following kwargs:
            terms: list of terms to search on
            sobject: SalesForce Object to search (None if search all)
            join_terms_on: AND (default) or OR
            returning_fields: Fields to include in results
        if no sobject specified, returning_fields are ignored
        """
        self.conn = connection
        self.terms = kwargs.get('terms', [])
        self.sobject = kwargs.get('sobject', None)
        self.join_terms_on = kwargs.get('join_terms_on', 'AND')
        return_fields = ['Id', 'Name']
        return_fields.extend(kwargs.get('returning_fields', []))
        self.fields = list(set(return_fields))
        self.returning_fields = self.fields

    def _make_returning(self):
        if self.sobject is None:
            return ''
        fields = ','.join(self.returning_fields)
        return '+RETURNING+%s+(%s)' % (self.sobject, fields)

    def _url(self):
        instance_url = self.conn.auth['instance_url']
        base = '%s/services/data/v39.0/search?q=' % instance_url
        find = 'FIND+{%s}+IN+ALL+FIELDS' % format_search_terms(
            self.terms, self.join_terms_on)
        url = ''.join([base, find, self._make_returning()])
        return '+'.join(url.split(' '))

    @to_be_deprecated('SOSL._search_url', 'SOSL._url')
    def _search_url(self):
        return self._url()

    def get_results(self):
        return QueryResult(self).records

    @to_be_deprecated('SOSL.results', 'SOSL.get_results')
    def results(self):
        return self.get_results()
