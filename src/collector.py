import time


class DataCollector:

    def __init__(self, filename):
        # initializing
        self.initial_time = time.time()
        self.file = open(filename, 'w')

    # return current time since object creating
    def current_time(self):
        return time.time() - self.initial_time

    # add information
    def add_point(self, count):
        self.file.write("{} {}\n".format(self.current_time(), count))

    def terminate(self):
        self.file.close()
        