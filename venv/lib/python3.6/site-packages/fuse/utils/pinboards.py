
class PinNotProcessed(Exception):
    pass

class Pinboard(object):

    def __init__(self):
        self.pin_id = None
        self.pins = {}
        self.PinNotProcessed = PinNotProcessed

    def get_pin_id(self):
        if self.pin_id is None:
            self.pin_id = 1
            return self.pin_id

        self.pin_id += 1
        return self.pin_id



    def post_pin(self, label, message):
        pin = Pin(label, message)
        pin_id = self.get_pin_id()

        self.pins[pin_id] = pin

        return pin_id

    def get(self, exclude):
        return [(pin_id, self.pins[pin_id]) for pin_id in self.pins if pin_id not in exclude]


class Pin(object):

    def __init__(self, label, message):
        self.label = label
        self.message = message
