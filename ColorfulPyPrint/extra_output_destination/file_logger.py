class FileLogger:
    def write(self, stream):
        with open(self.file_path, 'a', encoding=self.encoding) as fp:
            fp.write(stream + '\n')

    def __init__(self, filepath, encoding='utf-8'):
        self.file_path = filepath
        self.encoding = encoding
