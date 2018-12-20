from __future__ import absolute_import, division, print_function, unicode_literals
from fuse.components import Component
import os

class Home(Component):

    def setup(self, pinboard):
        pinboard.post_pin('home_directory', None)

    def home_directory(self, _):
        project_home = self.prompt(
            'directory',
            text="Project Home",
            default=os.getcwd(),
            prefill=self.prefill.get('directory', None),
            pre_validation_hook=os.path.expanduser
        )

        self.post_pin('current_working_directory', project_home)

