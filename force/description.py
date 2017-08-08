import re
import base64
from dateutil.parser import parse
from datetime import date, datetime, time
from fuzzywuzzy import fuzz
from .connect import Connection
from .idioms import Idiom
"""Handles interactions with describe objects from SF"""


def listify(raw):
    """
    Turns any input into a list
    """
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [v for k, v in raw.items()]
    return [raw]


def txt_only(raw):
    """
    Removes all non-alphanumeric chars from raw input

    Returns dict where:
        keys are input items
        vals are dicts with:
            'clean': cleansed input item
            'sterms': list of words in clean
    """
    raw = listify(raw)
    p = re.compile('[^0-9a-zA-Z_]+')
    op = {}
    for x in raw:
        try:
            op[x] = p.sub('_', x)
        except Exception as e:
            print(raw)
            print(x)
            raise e
    return {
        k: {
            'clean': v,
            'sterms': v.split('_')
        } for k, v in op.items()}


def cmd_menu(msg, unk, top, more=None, inpt=None, alt=''):
    """
    Creates command line menu given options

    msg: header message to display
    unk: Name of unknown value
    top: dict of label and top options
    more: dict of label and more options
    inpt: input value
    alt: optional alternative action:
        'drop': drop the unk from consideration
        'override': accept the inpt value regardless
    """

    # Show msg:
    print(msg)

    # idx is indexer for menu opts
    idx = 0
    opts = {}

    # offer alt functionality
    inpt = '' if inpt is None else inpt
    alts = {
        'drop': ('Drop field %s.' % unk, None,),
        'override': ('Force %s.' % inpt, inpt,),
        'other': ('New Search', None,)}
    if alt in alts.keys():
        print("%s.\t%s\n" % (str(idx), alts[alt][0]))
        opts[str(idx)] = alts[alt][1]

    # print options
    def prnt_opts(pidx, popts, opts_lst):
        print("%s:" % opts_lst['label'])
        for val in opts_lst['vals']:
            pidx += 1
            print("%s.\t%s" % (str(pidx), val))
            popts[str(pidx)] = val
        return pidx, popts

    idx, opts = prnt_opts(idx, opts, top)

    # offer to show more
    if more is not None:
        idx += 1
        print("\n%s.\tShow more options" % str(idx))
        opts[str(idx)] = 'show_more_12345'

    # collect input
    def get_sel(popts):
        print('')
        virng = [int(x) for x in popts.keys()]
        valid_rspnse = False
        while not valid_rspnse:
            tmp = input("Choose option (%s to %s): " % (
                str(min(virng)), str(max(virng))))
            valid_rspnse = tmp in popts.keys()
        return tmp

    sel = opts[get_sel(opts)]
    if sel == 'show_more_12345':
        idx, opts = prnt_opts(idx, opts, more)
        sel = opts[get_sel(opts)]
    return sel


class Description(object):

    def __init__(self, conn, obj_name):
        """
        Object representing sobject definition from Force API

        obj_name:
            Force API name of the sobject
        conn:
            Connection object from this package
        """

        # Check if connection is valid
        # must be an instance of Connection
        conn_valid = [isinstance(conn, Connection)]
        # copy conn.auth dict into local variable
        conn_auth = {} if not hasattr(conn, 'auth') else conn.auth
        # check if there's an access token in the auth dict
        conn_valid.append('access_token' in conn_auth)

        if False in conn_valid:
            raise RuntimeError('Invalid Connection: %s' % str(conn))

        # Otherwise set conn and obj_name as attributes
        self.conn = conn
        self.obj_name = obj_name

        # Check if object exists:
        resp = conn.req_get(self.url())

        if 'fields' not in resp.keys():
            raise RuntimeError('Invalid Object: %s' % str(resp))

        # Otherwise turn response keys into attributes
        for key in resp.keys():
            setattr(self, key, resp[key])

        # set idiomatic match mode to silent
        self.imm = True

        # create list of responses from inserts and updates
        self.api_responses = []

    def url(self):
        """
        Gives url for sobject description.
        """

        iurl = self.conn.auth['instance_url']
        return "%s/services/data/v37.0/sobjects/%s/describe" % (
            iurl, self.obj_name)

    def insert_required(self):
        """
        Returns list of fields required for an insert
        """
        createable = [x for x in self.fields if x['createable']]
        no_default = [x for x in createable if not x['defaultedOnCreate']]
        return [x for x in no_default if not x['nillable']]

    def get_field_obj(self, fname):
        """
        returns FieldDef of field specified

        fname:
            name or label of field in question
        """

        match = [x for x in self.fields if x['name'] == fname]
        match.extend([x for x in self.fields if x['label'] == fname])
        if len(match) == 0:
            raise RuntimeError("Cannot find %s in %s fields." % (
                fname, self.label))
        return FieldDef(self, match[0])

    def toggle_idiomatic_match_mode(self):
        """
        allows user to enable interface for idiomatic matches
        """
        self.imm = not self.imm
        mode_name = 'silent' if self.imm else 'verbose'
        msg = "Idiomatic matching mode switched to %s." % mode_name
        print(msg)

    def field_matching(self, raw_cols, expd_in_cols=None):
        """
        Returns dict with auto-matches and recommendations

        raw_cols is list of user fields to match
        expd_in_cols is list of expected columns
        """

        # if expd_in_cols is None, use insert_required list
        if expd_in_cols is None:
            expd_in_cols = self.insert_required()

        # clean text of column headers
        clean_cols = txt_only(raw_cols)

        # try to match column header to API field
        ufnms = {x['name']: x['label'] for x in self.fields}

        # fuzz ratios for sobject field labels and names
        for key, item in clean_cols.items():
            # matches is dict with k: fieldname, v: fuzz.ratio
            matches = {
                k: sum([
                    max(
                        fuzz.ratio(x, k),
                        fuzz.ratio(x, v)) for x in item['sterms']
                ])/len(item['sterms']) for k, v in ufnms.items()}
            matches = {
                k: max(
                    fuzz.ratio(item['clean'], k),
                    fuzz.ratio(item['clean'], ufnms[k]),
                    fuzz.ratio(key, k),
                    fuzz.ratio(key, ufnms[k]),
                    v) for k, v in matches.items()}
            matches = {v: k for k, v in matches.items()}
            scores = sorted(matches.keys(), reverse=True)
            item['top_score'] = scores[0]
            item['top_match'] = matches[scores[0]]
            item['next_4_closest'] = {
                v: k for k, v in matches.items() if k in scores[1:5]}

        # tms is a dict with k: expd_cols, v: input col names
        tms = {
            v['top_match']: k
            for k, v in clean_cols.items()
            if v['top_score'] > 69}

        # mapping adds remaining expd fields to tms with None as val
        mapping = {
            x: None if x not in tms.keys() else tms[x]
            for x in expd_in_cols}

        # count missing
        ignore_missing = []

        def missing():
            tmp = [x for x in expd_in_cols if x not in ignore_missing]
            return [x for x in tmp if mapping[x] is None]

        immms = []
        while len(missing()) > 1:
            unk = missing()[0]
            unks_idiom = Idiom(self.obj_name, 'column name', unk)
            unks_tm = unks_idiom.top_match()
            unks_tm = [] if not self.imm else [
                x for x in unks_tm if x in clean_cols.keys()]
            if len(unks_tm) == 1:
                sel = unks_tm[0]
                immms.append(
                    "%s -> %s" % (unk, sel))
            else:
                msg = "Select mapping for %s:" % unk
                used = [v for k, v in tms.items()]
                unused = [k for k in clean_cols.keys() if k not in used]
                top = {'label': 'Unused', 'vals': unused}
                more = {'label': 'Used', 'vals': used}
                sel = cmd_menu(msg, unk, top, more, inpt=None, alt='drop')
            if sel is None:
                ignore_missing.append(unk)
            else:
                mapping[unk] = sel
                unks_idiom.match_it(sel)

        if len(immms) > 0:
            msg = "Found idiomatic matches for:\n%s" % '\n'.join(immms)
            print(msg)

        return {v: k for k, v in mapping.items()}

    def check_insert(self, match_on=None, **kwargs):
        """ Runs pre-insert check.
        Reutrns dict with:
            given values
            valid values
            scored possible matches
        """

        # get fields for matching
        if match_on is None:
            match_on = []
            refs = [x['name'] for x in self.insert_required()]
            refs = [x for x in refs if x in kwargs.keys()]
            match_on.extend(refs)
        if not isinstance(match_on, list):
            match_on = [match_on]

        op = {'given': kwargs}
        validvals = self.pre_insert_check(**kwargs)
        op['valid'] = validvals

        field_names = ['Id']
        field_names.extend([x for x in kwargs.keys()])
        field_names = list(set(field_names))

        mterms = [v for k, v in validvals.items() if k in match_on]

        rslt = self.conn.search(mterms, self.name, field_names)

        def mscore(rec, vv):
            scores = [
                1 if v == rec.get(k) else 0 for k, v in vv.items()]
            return sum(scores) / len(scores)

        scored = [(mscore(x, validvals), x) for x in rslt]
        ranked = sorted(scored, reverse=True, key=lambda x: x[0])
        op['matches'] = [x[1] for x in ranked]
        return op

    def pre_insert_check(self, **kwargs):
        """
        Accepts kwargs for record to be created.

        Returns dict with valid values
        """

        # look up the required fields
        req_fields = [x['name'] for x in self.insert_required()]

        # put the required fields into the dict
        op = {x: None for x in req_fields}

        # add additional fields from given
        for k in kwargs.keys():
            op[k] = kwargs[k]

        # now that both required and supplied in one dict, cycle thru
        for k in op.keys():
            fo = self.get_field_obj(k)
            try:
                op[k] = fo.test_value(op[k])
            except Exception as e:
                print("Error testing %s, with val %s" % (k, op[k]))
                raise e

        return op

    def insert_rec(self, **kwargs):
        """
        Inserts record per kwargs

        Successful inserts return Id of inserted record

        full response stored in object last_resp
        """

        url = '%s/services/data/v37.0/sobjects/%s/' % (
            self.conn.auth['instance_url'], self.name)
        rspns = self.conn.req_post(url, kwargs)

        # make transaction dict
        ild = {'action': 'insert', 'data': kwargs}

        resp = {k.lower(): v for k, v in rspns.items()}

        ild['response'] = resp

        self.api_responses.append(ild)

        return resp.get('id')

    def update_rec(self, sfid=None, **kwargs):
        """
        Updates record
        """

        # Handle SFID
        tsfid = kwargs.get('Id', sfid)
        sfid = sfid if sfid is not None else tsfid
        if sfid is None:
            raise RuntimeError("No SFID provided.")
        if sfid != tsfid:
            msg = "Conflicting SFIDs given (%s and %s):" % (
                sfid, tsfid)
            raise RuntimeError(msg)
        payload = {k: v for k, v in kwargs.items() if k != 'Id'}

        # make url and send request
        url = '%s/services/data/v37.0/sobjects/%s/%s' % (
            self.conn.auth['instance_url'], self.name, sfid)
        result = self.conn.req_patch(url, payload)

        # make transaction dict
        uld = {'action': 'update', 'data': payload}

        # parse the response content
        try:
            response_content = result.json()
        # pylint: disable=broad-except
        except Exception:
            response_content = result.text

        uld['response'] = response_content

        # make sure result is not an error:
        if result.status_code >= 300:
            uld['errors'] = [result.status_code]

        self.api_responses.append(uld)

        return len(uld.get('errors', [])) == 0


class FieldDef():

    def __init__(self, parent, field):
        """
        Object representing one field from an sobject definition

        parent:
            Description object for sobject
        field:
            name, label, or dict from parent
        """

        # in case of user enters sobj name instead of Description object
        if not isinstance(parent, Description):
            try:
                # just use the default connection
                c = Connection()
                # try to create the parent object
                np = Description(c, parent)
                self.parent = np
            except Exception as e:
                msg = "Could not create field def for %s.%s: %s" % (
                    parent, field, str(e))
                raise RuntimeError(msg)
        else:
            self.parent = parent

        # if field is not a dict, then get the dict from parent
        if not isinstance(field, dict):
            match = [x for x in self.parent.fields if x['name'] == field]
            match.extend([
                x for x in self.parent.fields if x['label'] == field])
            if len(match) == 0:
                raise RuntimeError('Cannot find %s in %s fields.' % (
                    field, self.parent.label))
            field = match[0]

        # cycle thru the field def props and set each as an attribute
        for key in field.keys():
            setattr(self, key, field[key])

        # make sure there's a nillable attr
        if not hasattr(self, 'nillable'):
            self.nillable = True

    def __str__(self):
        nm = 'unnamed field' if not hasattr(self, 'name') else self.name
        lbl = 'unlabeled field' if not hasattr(self, 'label') else self.label
        return "%s (%s)" % (lbl, nm)

    def required_for_insert(self):
        """Boolean if field required for insert"""
        return self.name in [
            x['name'] for x in self.parent.insert_required()]

    def test_value(self, tval=None):
        """
        Tests proposed value against field rules

        provide user interface if not valid
        """

        # test null
        if tval is None:
            corr = input("Enter value for %s:" % str(self))
            if corr == '':
                if self.required_for_insert():
                    print("Required field. leave blank for value of 'abc'")
                    corr = input("Enter value for %s:" % str(self))
                    corr = 'abc' if corr == '' else corr
                else:
                    corr = None
            return self.check_SOAP(corr)

        # test calculated field
        if self.calculated:
            msg = 'SF will calculate %s. Type Y to override. ' % str(self)
            corr = input(msg)
            rtn = None if corr.upper().strip()[0] != 'Y' else tval
            return self.check_SOAP(rtn)

        # deprecatedAndHidden check
        if self.deprecatedAndHidden:
            msg = '%s is deprecated and hidden. Type Y keep.' % str(self)
            corr = input(msg)
            rtn = None if corr.upper().strip()[0] != 'Y' else tval
            return self.check_SOAP(rtn)

        # test picklist
        if len(self.picklistValues) > 0:
            return self.check_SOAP(self.test_picklistVal(tval))

        # test reference
        if self.referenceTo:
            return self.check_SOAP(self.test_reference(tval))

        # otherwise all good
        return self.check_SOAP(tval)

    def test_picklistVal(self, tval):
        """
        Returns corrected value
        """

        # match value to pl values
        try:
            if not isinstance(tval, str):
                tval = str(tval)
        except Exception as e:
            tval = ''

        pl = self.picklistValues
        match = [x for x in pl if x['value'] == tval]
        if len(match) > 0:
            return tval

        # check idioms
        ctxt = 'value_%s' % self.parent.conn.env
        tidiom = Idiom(self.parent.obj_name, ctxt, tval)
        tm = tidiom.top_match()
        if len(tm) == 1 and self.parent.imm:
            tidiom.match_it(tm[0])
            return(tm[0])

        # match value to pl labels
        msg = '"%s" is not in the picklist for %s.\n' % (
            tval, str(self))
        match = [(
            x['value'],
            max([
                fuzz.ratio(tval, x['value']),
                fuzz.ratio(tval, x['label'])]),
            )
            for x in pl]
        match = sorted(
            match,
            reverse=True,
            key=lambda x: x[1])
        tl = 'Values'
        more = None
        if len(match) > 5:
            tl = 'Closest matches'
            more = {
                'label': 'Others',
                'vals': [x[0] for x in match[5:]]}
        top = {'label': tl, 'vals': [x[0] for x in match[:5]]}
        alt = '' if self.restrictedPicklist else 'Override'
        sel = cmd_menu(
            msg,
            str(self),
            top,
            more,
            inpt=tval,
            alt=alt)
        tidiom.match_it(sel)
        return sel

    def test_reference(self, tval):
        """
        Returns corrected value
        """

        # get basic info
        ref_objs = self.referenceTo
        pconn = self.parent.conn
        srslts = []

        # check_id func queries for Id
        def check_id(pc, sobj, tid):
            soql = "SELECT Id FROM %s WHERE Id='%s'" % (sobj, tid)
            try:
                rslt = pc.query(soql)
                if len(rslt) > 0:
                    return True
            except Exception as e:
                pass
            return False

        # search_obj func searches for text
        def search_obj(pc, sobj, ttxt):
            return pc.search(ttxt, sobj)

        # check idioms
        ctxt = 'value_%s' % self.parent.conn.env
        tidiom = Idiom(self.parent.obj_name, ctxt, tval)
        tm = tidiom.top_match()
        if len(tm) == 1 and self.parent.imm:
            tidiom.match_it(tm[0])
            return(tm[0])

        # check if the value is an sfid or in search
        ntrm = tval
        while True:

            # check if the value is an sfid or in search
            for ref_obj in ref_objs:
                if check_id(pconn, ref_obj, ntrm):
                    tidiom.match_it(ntrm)
                    return ntrm
                srslts.extend(search_obj(pconn, ref_obj, ntrm))

            # if one result
            if len(srslts) == 1:
                tidiom.match_it(srslts[0]['Id'])
                return srslts[0]['Id']

            # if multiple results
            elif len(srslts) > 1:
                match = [(
                    '%s: %s (%s)' % (
                        x['attributes.type'],
                        x['Name'],
                        x['Id']),
                    x['Id'],
                    fuzz.ratio(ntrm, x['Name']))
                    for x in srslts]
                match = sorted(match, reverse=True, key=lambda x: x[2])
                tl = 'Possible matches'
                more = None
                if len(match) > 5:
                    tl = 'Closest matches'
                    more = {
                        'label': 'Other matches',
                        'vals': [x[0] for x in match[5:]]}
                top = {'label': tl, 'vals': [x[0] for x in match[:5]]}
                msg = '%s possible matches found for %s in %s.' % (
                    str(len(srslts)), ntrm, str(self))
                usr_rsp = None
                usr_rsp = cmd_menu(
                    msg,
                    str(self),
                    top,
                    more,
                    inpt=ntrm,
                    alt='other')
                tmp = [x[1] for x in match if x[0] == usr_rsp]
                if len(tmp) > 0:
                    ntrm = tmp[0]
                else:
                    srslts = []

            # if no results
            elif len(srslts) == 0:
                msg = '%s not found for %s. Enter new search term: ' % (
                    ntrm, str(self))
                ntrm = input(msg)

    def dflt_val(self):
        """ Returns Force Default Value for field """
        if not hasattr(self, 'defaultValue'):
            return None
        return self.defaultValue

    def type_def(self):
        defined_types = {
            'tns:ID': 'cs_id',
            'xsd:anyType': 'cs_any',
            'xsd:base64Binary': 'cs_b64',
            'xsd:boolean': 'cs_bool',
            'xsd:date': 'cs_date',
            'xsd:dateTime': 'cs_datetime',
            'xsd:double': 'cs_double',
            'xsd:int': 'cs_int',
            'xsd:string': 'cs_str'}
        return defined_types.get(self.soapType, 'cs_any')

    def soql_syntax(self, tval):
        quoted = self.soapType in ['tns:ID', 'xsd:string']
        if self.soapType == 'xsd:anyType':
            quoted = isinstance(tval, str)

        if tval is None:
            return None
        elif quoted:
            return "%s='%s'" % (self.name, tval)
        else:
            return "%s=%s" % (self.name, tval)

    def check_SOAP(self, tval):
        """
        Tests value against defined SOAPType rules
        """

        # check if field SOAPType is defined
        ptype = self.type_def()

        # run the appropriate check
        return getattr(self, ptype)(tval)

    def cs_str(self, tval):
        """ Test string value """
        try:
            tval = str(tval)
        except Exception as e:
            if self.nillable:
                return None
            dv = self.dflt_val()
            tval = '' if dv is None else dv
        slen = len(tval) if not hasattr(self, 'length') else self.length
        if slen > 0 and slen < len(tval):
            tval = tval[:slen]
        return tval

    def cs_int(self, tval):
        """ Test string value """
        try:
            tval = int(tval)
        except Exception as e:
            if self.nillable:
                return None
            dv = self.dflt_val()
            if dv is None:
                raise e
            tval = dv
        if hasattr(self, 'digits'):
            ml = int(self.digits)
            tstr = [str(0)] * ml
            tstr.extend([x for x in str(tval)])
            ml = ml * -1
            tval = int(''.join(tstr[ml:]))
        return tval

    def cs_double(self, tval):
        """ Test double value """
        try:
            tval = float(tval)
        except Exception as e:
            if self.nillable:
                return None
            dv = self.dflt_val()
            tval = float() if dv is None else dv
        return tval

    def cs_datetime(self, tval, eloop=False):
        """ Test datetime value """
        if not isinstance(tval, (datetime, date)):
            try:
                tval = parse(tval)
                tval = datetime.combine(tval, time())
            except Exception as e:
                if self.nillable:
                    return None
                dv = self.dflt_val()
                if not eloop and dv is not None:
                    return self.cs_datetime(dv, True)
                raise e
        return "%sZ" % tval.isoformat(timespec='milliseconds')

    def cs_date(self, tval):
        """ Test date value """
        tval = self.cs_datetime(tval)
        if tval is None:
            return None
        tval = parse(tval)
        tval = tval.date()
        return tval.isoformat()

    def cs_bool(self, tval):
        """ Test boolean value """
        if isinstance(tval, bool):
            return tval

        if isinstance(tval, str):
            if tval.upper() == 'FALSE':
                return False
            if tval.upper() == 'TRUE':
                return True

        if self.nillable:
            return None

        dv = self.dflt_val()
        if not isinstance(dv, bool):
            raise RuntimeError("%s must be a boolean." % str(self))
        return dv

    def cs_b64(self, tval):
        """ Test Base64 value """
        if not isinstance(tval, bytes):
            try:
                tval = bytes(tval, 'utf8')
            except Exception as e:
                if self.nillable:
                    return None
                dv = self.dflt_val()
                if dv is None:
                    raise e
                tval = bytes(dv, 'utf8') if not isinstance(dv, bytes) else dv

        return base64.b64encode(tval)

    def cs_any(self, tval):
        return tval

    def cs_id(self, tval):
        """ Tests id """
        tval = self.cs_str(tval)
        if len(tval) not in [15, 18]:
            raise RuntimeError("%s is not a valid SFID for %s." % (
                tval, str(self)))
        return tval


if __name__ == '__main__':
    pass
