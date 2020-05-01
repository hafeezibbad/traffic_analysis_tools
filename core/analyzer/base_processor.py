from abc import ABC


class BaseProcessorABC(ABC):
    @staticmethod
    def process():
        pass


class BaseProcessor(BaseProcessorABC):
    """Base class for all processors."""
    def process(self, input_file: str = None, output_file: str = None):
        """Process input file to generate output file

        Parameters
        ----------
        input_file: str
            File containing the data which needs to be processed
        output_file: str
            File where processed data needs to be written
        """
        raise NotImplementedError
