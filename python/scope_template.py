import collections
import json
class ScopeTemplate:
#(collections.namedtyple('ScopeTemplate', ['name', 'bytes_thresh'], verbose=False):

    __thresholds = None

    def __str__(self):
        return 'Template: ' + str(self.name) + str(self.__thresholds)

    def __init__(self, name, bytes_thresh):
        self.name = name
        self.__thresholds = []
        # Each byte_thresh is in the form of ('>'|'<'|'='|'>='|'<=) + digit(s)
        for bt in bytes_thresh:
            thresh_level = {}
            digit_idx = 1 if bt[1].isdigit() else 2
            thresh_level['op'] = bt[:digit_idx]
            thresh_level['bytes'] = int(bt[digit_idx:])
            self.__thresholds.append(thresh_level)

    def num_levels(self):
        return len(self.__thresholds)

    def compare(self, num_bytes, level):
        if self.num_levels() < level:
            return False
        op = self.__thresholds[level]['op']
        val = self.__thresholds[level]['bytes']
        if op == '<':
            return num_bytes < val
        if op == '>':
            return num_bytes > val
        if op == '=':
            return num_bytes == val
        if op == '>=':
            return num_bytes >= val
        if op == '<=':
            return num_bytes <= val
        return False

    def to_json(self):
        return json.dumps(self.__dict__, indent=4)

