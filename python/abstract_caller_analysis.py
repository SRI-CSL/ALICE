from instruction import *
from abc import abstractmethod
import angr

class AbstractCallerAnalysis(angr.Analyses):
#class AbstractCallerAnalysis:

    def __init__(self, binary, deepcopy=False):
        if not isinstance(binary, Binary):
            raise TypeError("Type is not Binary: ", type(binary))
        self.binary = binary.copy() if deepcopy else binary
        super(AbstractCallerAnalysis, self).__init__(self.binary.angr_proj)

    @abstractmethod
    def code_refs(self, vaddr):
        pass


    @abstractmethod
    def data_refs(self, start_vaddr, end_vaddr=None):
        pass
