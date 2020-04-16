from abc import ABC


class BaseProcessorABC(ABC):
    @staticmethod
    def process():
        pass


class BaseProcessor(BaseProcessorABC):
    """Base class for all processors."""
    def process(self, input_file: str = None, output_file: str = None):
        """

        :param input_file: File containing the data which needs to be processed
        :param output_file: File where processed data needs to be written
        :return:
        """
        raise NotImplementedError
