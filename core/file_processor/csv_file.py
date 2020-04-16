from core.file_process.base import FileProcessorABC


class CsvFileProcessor(FileProcessorABC):
    def read(self, file_path: str) -> bool:
        # TODO: Implement
        pass

    def write(self, content: list, output_file_path: str) -> bool:
        # TODO: Implement
        pass
