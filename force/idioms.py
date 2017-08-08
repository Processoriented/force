import os
import json
"""Handles idoms for matching"""


def create_idiom_file():
    """If no idiom file exists, create it, otherwise return existing"""
    cp = os.path.split(__file__)
    fp = os.path.join(cp[0], 'idioms.json')
    if not os.path.exists(fp):
        tmp = {}
        with open(fp, 'w') as f:
            json.dump(tmp, f)
    return fp


def get_depth(obj, level=1):
    """Returns depth of nested object"""
    if isinstance(obj, dict):
        return max(get_depth(v, level + 1) for k, v in obj.items())
    if isinstance(obj, list):
        return max(get_depth(x, level + 1) for x in obj)
    return level


class Idiom():
    def __init__(self, sobj, context, term):
        """
        Looks up or creates idiom for given object, context and term

        sobj:
            Salesforce Object to which the idiom applies
        context:
            Name of search context e.g. column name, value
        term:
            search term given in lookup

        Matches are a dict where the key is the
        resulting match and the value is a count of times
        this match was used
        """
        self.sobj = sobj
        self.context = context
        self.term = term

        # get stored idiom objects
        fp = create_idiom_file()
        self.all_idioms = None
        with open(fp, 'r') as f:
            self.all_idioms = json.load(f)
        self.fp = fp

    def matches(self):
        """
        Checks if idiom is already stored and creates if not
        """

        # Check if storage required
        needs_store = False
        if self.sobj not in self.all_idioms.keys():
            self.all_idioms[self.sobj] = {}
            needs_store = True
        if self.context not in self.all_idioms[self.sobj].keys():
            self.all_idioms[self.sobj][self.context] = {}
            needs_store = True
        if self.term not in self.all_idioms[self.sobj][self.context].keys():
            self.all_idioms[self.sobj][self.context][self.term] = {}
            needs_store = True
        if needs_store:
            self.store_idioms()
        return self.all_idioms[self.sobj][self.context][self.term]

    def store_idioms(self):
        """Stores idioms in file"""
        idioms = self.all_idioms
        with open(self.fp, 'w') as f:
            json.dump(idioms, f, indent=get_depth(idioms))

    def top_match(self):
        """Returns top match if there is one"""

        # If no matches return empty list
        if len([x for x in self.matches().keys()]) == 0:
            return []

        # get and sort the list of matches previously used
        mtch_lst = [(k, v) for k, v in self.matches().items()]
        srtd = sorted(mtch_lst, reverse=True, key=lambda x: x[1])

        # check if there are any ties
        top_score = srtd[0][1]
        return [x[0] for x in srtd if x[1] == top_score]

    def match_it(self, matched):
        """
        Accepts a matched value
        If already present, increment score
        If not, add and set score to 1
        """

        # look up match
        if matched in self.matches().keys():
            self.matches()[matched] += 1
        else:
            self.matches()[matched] = 1

        # store update
        self.store_idioms()
