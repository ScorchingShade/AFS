from __future__ import absolute_import, division, print_function, unicode_literals
from cement.utils.shell import Prompt

class BasePrompt(Prompt):
    class Meta:
        max_attempts = 99
        auto = True

    def __init__(
            self,
            identifier,
            text=None,
            description=None,
            default=None,
            validators=None,
            options=None,
            pre_validation_hook=None,
            prefill=None,
    ):

        self.identifier = identifier
        self.text = identifier if text is None else text
        self.validators = validators
        self.pre_validation_hook = pre_validation_hook

        if not default is None:
            self.text += " (default: %s)" % default
        self.text += ":"

        super(BasePrompt, self).__init__(text=self.text, default=default, options=options, auto=False)

    def is_valid(self, value):
        return all(validator(value) for validator in self.validators)

    def get_validation_text(self):
        rules = [validator.__doc__.strip() for validator in self.validators if validator.__doc__]

        return '\n'.join(["%i) %s" % (i+1, rule) for i, rule in enumerate(rules)])

    def prompt(self):
        """
        Prompt the user, and store their input as `self.input`.
        """

        attempt = 0

        if self.input is not None and self.pre_validation_hook:
            self.input = self.pre_validation_hook(self.input)

        while self.input is None or not self.is_valid(self.input):
            if attempt >= int(self._meta.max_attempts):
                if self._meta.max_attempts_exception is True:
                    raise FrameworkError("Maximum attempts exceeded getting "
                                         "valid user input")
                else:
                    return self.input

            attempt += 1
            self._prompt()

            if self.input is not None and self.pre_validation_hook:
                self.input = self.pre_validation_hook(self.input)

            if self.input is None or not self.is_valid(self.input):
                if attempt == 1:
                    self._meta.text = self.get_validation_text() + '\n' + self._meta.text
                continue
            elif self._meta.options is not None:
                if self._meta.numbered:
                    try:
                        self.input = self._meta.options[int(self.input) - 1]
                    except (IndexError, ValueError) as e:
                        self.input = None
                        continue
                else:
                    if self._meta.case_insensitive is True:
                        lower_options = [x.lower()
                                         for x in self._meta.options]
                        if not self.input.lower() in lower_options:
                            self.input = None
                            continue
                    else:
                        if self.input not in self._meta.options:
                            self.input = None
                            continue

        return self.input

class DefaultPrompt(BasePrompt):
    pass

class NullPrompt(BasePrompt):
    def prompt(self):
        self.input = ''
