class GenericError(Exception):
    def __init__(self, message):
        self.message = message

    def __repr__(self):
        print(self.message)

    def __str__(self):
        self.__repr__()
