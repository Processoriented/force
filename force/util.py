import collections
import re
import warnings


def flatten(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def first_instance(given, term):
    given = given.upper()
    if term in given:
        return given.index(term)
    return len(given)


def escape_specials(text):
    """Escape any special characters in text for a url"""
    rsvd = r'(\?|\&|\||\!|\{|\}|\[|\]|\(|\)|\^|\~|\*|\:|\\|\"|\'|\+|\-)'
    p = re.compile(rsvd)
    return p.sub(r'\\\1', text)


def format_search_terms(terms, joinon='AND'):
    """
    Formats a list of search terms for SOSL searches.
    Joiner may be AND or OR depending on desired behavior of search
    """
    joiner = '" %s "' % joinon.upper()
    cterm = joiner.join([escape_specials(x) for x in terms])
    return cterm if len(terms) < 2 else '"%s"' % cterm


def to_be_deprecated(used, replacement):
    """Throws a warning whenever a to-be-deprecated function/class is called"""
    def show_warning(function):
        def wrapper(*args, **kwargs):
            message = '%s will be deprecated.\n' % used
            message += 'Please update code to use %s instead.\n' % replacement
            warnings.warn(message, FutureWarning)
            return function(*args, **kwargs)
        return wrapper
    return show_warning
