from core.file_processor.base import FileProcessorABC


class CsvFileProcessor(FileProcessorABC):
    def read(self, file_path: str) -> bool:
        # TODO: Implement
        pass

    def write(self, data: list, output_file_path: str) -> bool:
        # TODO: Implement
        pass
