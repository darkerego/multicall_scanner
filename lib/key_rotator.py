from itertools import cycle


class KeyRotator:
    def __init__(self, keys: list, key_file: str = None):
        self.key_lst = keys
        self.keys = self.init(key_file)

    def init(self, key_file = None):
        if key_file:
            self.load_keys(key_file)
            return cycle(self.key_lst)

    def key(self):
        return next(self.keys)

    def load_keys(self, key_file):
        with open(key_file, 'r') as f:
            [self.key_lst.append(k.strip("\r\n")) for k in f.readlines()]

