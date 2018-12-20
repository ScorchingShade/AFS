from __future__ import absolute_import, division, print_function, unicode_literals
from fuse.components import Component
import os

class Virtualenv(Component):

    def setup(self, pinboard):
        pinboard.post_pin('virtualenv_python_major_version', None)
        pinboard.post_pin('virtualenv_prompt', None)
        pinboard.post_pin('virtualenv_directory', None)

    def current_working_directory(self, project_home):
        self.config['project_home'] = project_home

    def virtualenv_python_major_version(self, _):
        self.config['python_major_version'] = self.prompt(
            'python_major_version',
            text="Python Major Version",
            options=['2','3'],
            prefill=self.prefill.get('python_major_version', None),
        )

    def virtualenv_prompt(self, _):
        self.config['prompt'] = self.prompt(
            'prompt',
            text="Prompt for virtualenv",
            default="(env) ",
            prefill=self.prefill.get('prompt', None),
        )

    def virtualenv_directory(self, _):
        if not 'project_home' in self.config:
            raise self.pinboard.PinNotProcessed

        def make_local_absolut(directory):
            absolut_dir = directory if directory[0] == '/' else os.path.join(self.config['project_home'], directory)
            return absolut_dir

        directory = self.prompt(
            'directory',
            text="Directory",
            description="Local (to project home) or absolute directory",
            default='env/',
            pre_validation_hook=make_local_absolut,
            prefill=self.prefill.get('directory', None),
        )

        self.config['directory'] = directory = make_local_absolut(directory)

        if directory.startswith(self.config['project_home']):
            local_dir = directory.replace(self.config['project_home'], '')
            self.post_pin('no_version_control', os.path.join(local_dir, '*'))


    def write(self):
        try:
            os.makedirs(self.config['directory'])
        except OSError:
            pass

        command = "/usr/local/bin/virtualenv -p python{python_major_version} --quiet --prompt=\"{prompt}\" {directory}"
        command = command.format(**self.config)

        os.system(command)

