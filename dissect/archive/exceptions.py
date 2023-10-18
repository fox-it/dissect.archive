class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class NotADirectoryError(Error):
    pass


class FileNotFoundError(Error):
    pass


class NotAReparsePointError(Error):
    pass
