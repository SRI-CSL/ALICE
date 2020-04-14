

class AliceArg:

    TYPE_BYTE_POINTER = 1
    TYPE_INT = 3

    def __init__(self, argtype, val, ref=None, expected_out=None):
        self.type = argtype
        self.val = val
        self.ref_val = ref
        self.expected_output = expected_out
        self.output = None

    def copy(self):
        return AliceArg(self.type, self.val, self.ref_val, self.expected_output)