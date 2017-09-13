import force as sf
from dateutil.parser import parse
from datetime import date, datetime, time


DEFINED_TYPES = {
    'tns:ID': 'cs_id',
    'xsd:anyType': 'cs_any',
    'xsd:base64Binary': 'cs_b64',
    'xsd:boolean': 'cs_bool',
    'xsd:date': 'cs_date',
    'xsd:dateTime': 'cs_datetime',
    'xsd:double': 'cs_double',
    'xsd:int': 'cs_int',
    'xsd:string': 'cs_str'}


def looks_like_id(term):
    if not isinstance(term, str):
        return False
    if term != term.replace(' ', ''):
        return False
    return len(term) in [15, 18]


class ForceDescription():
    def __init__(self, conn, name):
        self.conn = conn
        url = '%s/services/data/v37.0/sobjects/%s/describe' % (
            self.conn.auth['instance_url'], name)
        desc = self.conn.req_get(url)
        self.childRelationships = [
            ChildRelationship(self, **x) for x in desc.get(
                'childRelationships', [])]
        self.fields = [Field(self, **x) for x in desc.get('fields', [])]
        self.label = desc.get('label', '')
        self.labelPlural = desc.get('labelPlural', '')
        self.name = desc.get('name', name)
        self.recordTypeInfos = [RecordTypeInfo(self, **x) for x in desc.get(
            'recordTypeInfos', [])]

    def get_field_description(self, field_name):
        filtered = [x for x in self.fields if x.name == field_name]
        if len(filtered) == 0:
            return None
        return filtered[0]

    def insert(self, **kwargs):
        url = '%s/services/data/v37.0/sobjects/%s/' % (
            self.conn.auth['instance_url'], self.name)
        response = self.conn.req_post(url, kwargs)
        return response.get('id')

    def update(self, **kwargs):
        sfid = kwargs['Id']
        payload = {k: v for k, v in kwargs.items() if k != 'Id'}
        url = '%s/services/data/v37.0/sobjects/%s/%s' % (
            self.conn.auth['instance_url'], self.name, sfid)
        response = self.conn.req_patch(url, payload)
        return response.status_code < 300


class DescriptionChild():
    def __init__(self, parent, **kwargs):
        self.parent = parent
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)

    def set_default_attr(self, attr_name, default_val):
        val_to_set = getattr(self, attr_name, default_val)
        val_to_set = val_to_set if val_to_set is not None else default_val
        setattr(self, attr_name, val_to_set)


class ChildRelationship(DescriptionChild):
    def __init__(self, parent, **kwargs):
        super(ChildRelationship, self).__init__(parent, **kwargs)


class Field(DescriptionChild):
    def __init__(self, parent, **kwargs):
        self.picklistValues = [PicklistValue(self, **x) for x in kwargs.get(
            'picklistValues', [])]
        super(Field, self).__init__(parent, **kwargs)
        self.set_default_attr('nillable', True)
        self.set_default_attr('calculated', False)
        self.set_default_attr('length', 0)
        self.set_default_attr('soapType', 'xsd:anyType')
        self.set_default_attr('referenceTo', [])
        self.set_default_attr('referenceTargetField', None)

    def test_proposed(self, proposed_value):
        result = ProposedFieldValue(self, proposed_value)
        return (result.valid, result.replacement, result.errors)

    def get_matching_picklist_value(self, proposed_value):
        exact = [x for x in self.picklistValues if x.value == proposed_value]
        if len(exact) == 1:
            return (exact, [])
        elif len(exact) > 1:
            return (exact[0], exact[1:])
        return (
            None,
            [x for x in self.picklistValues if x.label == proposed_value])

    def target_field(self):
        target_field = self.referenceTargetField
        return 'Id' if target_field is None else target_field

    def query_id(self, proposed_value):
        return sf.SOQL(
            self.parent.conn,
            fields=[self.target_field()],
            sobject=self.referenceTo[0],
            filters="Id='%s'" % proposed_value).get_results()

    def lookup_related(self, proposed_value):
        if len(self.referenceTo) == 0:
            return (False, [])
        results = []
        target_field = self.target_field()
        if looks_like_id(proposed_value):
            results.extend(self.query_id(proposed_value))
        if len(results) == 0:
            for referenceTo in self.referenceTo:
                results.extend(sf.SOSL(
                    self.parent.conn,
                    terms=[proposed_value],
                    sobject=referenceTo,
                    returning_fields=[target_field]).get_results())
        if len(results) == 0:
            return (False, [])
        exact = [x for x in results if x[target_field] == proposed_value]
        if len(exact) == 1:
            return (
                proposed_value == exact[0][target_field],
                [exact[0][target_field]])
        for result in results:
            score = sum([v == proposed_value for k, v in result.items()])
            result['score'] = score
        ranked = sorted(results, reverse=True, key=lambda x: x['score'])
        return (False, [x[target_field] for x in ranked])


class PicklistValue(DescriptionChild):
    def __init__(self, parent, **kwargs):
        super(PicklistValue, self).__init__(parent, **kwargs)
        self.set_default_attr('label', '')
        self.set_default_attr('value', '')


class RecordTypeInfo(DescriptionChild):
    def __init__(self, parent, **kwargs):
        super(RecordTypeInfo, self).__init__(parent, **kwargs)


class ProposedFieldValue():
    def __init__(self, field, value):
        self.field = field
        self.value = value
        self.replacement = None
        self.errors = []
        self.valid = self.test_proposed()

    def get_type_def(self):
        defined_types = {
            'tns:ID': 'test_proposed_any',
            'xsd:anyType': 'test_proposed_any',
            'xsd:base64Binary': 'test_proposed_any',
            'xsd:boolean': 'test_proposed_bool',
            'xsd:date': 'test_proposed_date',
            'xsd:dateTime': 'test_proposed_datetime',
            'xsd:double': 'test_proposed_double',
            'xsd:int': 'test_proposed_int',
            'xsd:string': 'test_proposed_any'}
        return defined_types.get(self.field.soapType, 'test_proposed_any')

    def test_proposed(self):
        if self.value is None:
            return self.test_nillable()
        return getattr(self, self.get_type_def())()

    def test_nillable(self):
        if not self.field.nillable:
            self.errors.append('Not Nillable')
            self.replacement = None
            return False
        return True

    def test_stringify(self):
        try:
            str(self.value)
        except Exception as e:
            return False
        return True

    def test_length(self):
        if not self.test_stringify():
            return True
        if self.field.length == 0:
            return True
        if len(str(self.value)) > self.field.length:
            self.errors.append('Too Long')
            self.replacement = str(self.value)[:self.field.length]
            return False
        return True

    def test_picklist(self):
        if len(self.field.picklistValues) == 0:
            return True
        exact, near = self.field.get_matching_picklist_value(self.value)
        if len(near) > 0:
            self.replacement = near[0].value
        if exact is None:
            self.errors.append('Not in picklist')
            return False
        return True

    def test_reference(self):
        if len(self.field.referenceTo) == 0:
            return True
        exact, near = self.field.lookup_related(self.value)
        if exact:
            return True
        self.errors.append('No Exact Match in Reference')
        if len(near) > 0:
            self.replacement = near[0]
        return False

    def test_proposed_any(self):
        if self.field.calculated:
            self.errors.append('Calculated Field')
            self.replacement = None
            return False
        if not self.test_length():
            return False
        if not self.test_picklist():
            return False
        if not self.test_reference():
            return False
        return True

    def test_proposed_bool(self):
        if isinstance(self.value, bool):
            self.errors.append('Boolean Field')
            self.replacement = str(self.value).lower()
            return False
        try:
            bool(self.value)
        except Exception as e:
            self.errors.append('Boolean Field')
            return False
        return True

    def test_proposed_datetime(self):
        if not isinstance(self.value, (datetime, date)):
            try:
                replacement = parse(self.value)
                replacement = datetime.combine(replacement, time())
                formatted = "%sZ" % replacement.isoformat(
                    timespec='milliseconds')
                if self.value == formatted:
                    self.value = replacement
                    return True
                self.errors.append('Use Replacement')
                self.replacement == replacement
            except Exception as e:
                replacement = None
                self.replacement = None
                self.errors.append('Cannot Parse Date')
            return False
        return True

    def test_proposed_date(self):
        if self.test_proposed_datetime():
            self.value = self.value.date()
            return True
        return False

    def test_proposed_double(self):
        try:
            float(self.value)
        except Exception as e:
            self.errors.append('Double Field')
            return False
        return True

    def test_proposed_int(self):
        try:
            int(self.value)
        except Exception as e:
            self.errors.append('Int Field')
            return False
        return True
