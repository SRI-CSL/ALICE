from abc import abstractmethod
from elf_binary import *

class FunctionScope:

    def __init__(self, entry, exit):
        self.entry = entry
        self.exit = exit


class AbstractScoper:

    def __init__(self, binary, deepcopy=False):
        if not isinstance(binary, ElfBinary):
            raise TypeError("Type is not Binary: ", type(binary))
        self.binary = binary.copy() if deepcopy else binary

    # Return entry and exit points a function F that contains ``address"
    # and functions that call F upto ``height"
    # E.g. if F is called by A and B, A is called by C and D, and B is called by E
    # This function returns F if height is 1
    #               returns F, A, B if height is 2
    #               returns F, A, B, C, D, E if height is 3
    @abstractmethod
    def get_hierarchical_scopes(self, address, height):
        pass

    # Return a bound (entry and exit points) of a function
    # that contains ``address"
    @abstractmethod
    def get_function_scope(self, address):
        pass
