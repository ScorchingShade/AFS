from __future__ import absolute_import, division, print_function, unicode_literals
from fuse import models

class Component(object):

    def __init__(self,
                 name,
                 prompter,
                 prompts,
                 resources,
                 validators,
                 prefill=None,
                 ):

        self.name = name
        self.prefill = prefill
        self.prompter = prompter
        self.prompts = prompts
        self.resources = resources
        self.validators = validators

        self.config = {}
        self.processed_pins = []

        if self.prefill is None:
            self.prefill = {}

    def setup(self, pinboard):
        pass

    def configure(self, pinboard):
        """
        Process pins from pinboard and return number of pins processed
        """
        pins = pinboard.get(exclude=self.processed_pins)
        processed_pins = []

        for pin_id, pin in pins:
            if not hasattr(self, pin.label):
                processed_pins.append(pin_id)
                continue

            try:
                getattr(self, pin.label)(pin.message)
                processed_pins.append(pin_id)
            except pinboard.PinNotProcessed:
                pass
            
        self.processed_pins += processed_pins

        return len(processed_pins)


    def prompt(self, identifier, **parameters):
        # Fill in empty parameters from persistent storage if present
        try:
            default_parameters = self.prompts.get(identifier=identifier)

            for p in ['text', 'description', 'default', 'validators', 'options']:
                parameters.setdefault(p, getattr(default_parameters, p))

        except self.prompts.DoesNotExist:
            pass

        # Replace validator descriptors with actual functions
        if parameters.get('validators', None) is None:
            parameters['validators'] = []
        else:
            parameters['validators'] = [getattr(self.validators, validator) for validator in parameters['validators'].split(',')]

        # Split options to list if it's a string
        if type(parameters.get('options', None)) is str:
            parameters['options'] = parameters['options'].split(',')


        # Set the default value to prefill (if present)
        if parameters.get('prefill', None) is not None:
            parameters['default'] = parameters['prefill']

        # Setup prompter and set its input value
        prompter = self.prompter(identifier=identifier, **parameters)
        prompter.input = parameters.get('prefill', None)

        prompter.prompt()

        # Store input value under designate key and return the value
        return prompter.input

    def write(self):
        result = models.Resource.select().where(models.Resource.component == self.name)

        def in_version_span(sample, span):
            if sample is None:
                return True

            sample = semantic_version.Version(sample)
            span = [point if point is None else semantic_version.Version(point) for point in span]

            return (span[0] is None or span[0] <= sample) and (span[1] is None or span[1] >= sample)

        # Filter out all non-applicable versions and sort the remaining entries
        # by key 'from_version' (priority will be correlated with key 'from_version').

        resources = []
        for row in result:
            if not in_version_span(self.config.get('version', None), (row.from_version, row.to_version)):
                continue
            resources.append(row)

        resources.sort(
            key=lambda row: row.from_version,
            reverse=True,
        )

        for resource in resources:
            resource.write(self.config)


