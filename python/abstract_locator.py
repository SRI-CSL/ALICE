from abc import abstractmethod
from binary import *

class AbstractLocator:

    def __init__(self, binary, deepcopy=False):
        if not isinstance(binary, Binary):
            raise TypeError("Type is not Binary: ", type(binary))
        self.binary = binary.copy() if deepcopy else binary


    @abstractmethod
    def contain(self, crypto_desc):
        pass

    # Return a list of addresses that implements ``crypto_desc"
    # Ideally if multiple addresses are belong to the same basic block
    # only the lowest address should be included.
    @abstractmethod
    def get_address_locations(self, crypto_desc):
        pass