from __future__ import absolute_import, division, print_function, unicode_literals
from fuse.components import Component
import semantic_version
import re

class Django(Component):

    def setup(self, pinboard):
        pinboard.post_pin('django_project_name', None)
        pinboard.post_pin('django_project_slug', None)
        pinboard.post_pin('django_version', None)

    def current_working_directory(self, project_home):
        self.config['project_home'] = project_home

    def django_project_name(self, _):
        self.config['project_phrase'] = self.prompt(
            'project_name',
            prefill=self.prefill.get('project_name', None),
        )

    def django_project_slug(self, _):
        if not 'project_phrase' in self.config:
            self.repost_pin(self.next_pin - 1)
            return

        self.config['project_name'] = self.prompt(
            'project_slug',
            default=re.sub('[^0-9a-zA-Z]+', '_', self.config['project_phrase'].lower()),
            prefill=self.prefill.get('project_slug', None),
        )

    def django_version(self, _):
        django_version = self.prompt(
            'semantic_version',
            prefill=self.prefill.get('semantic_version', None),
        )

        django_version = semantic_version.Version(django_version)
        self.config['docs_version'] = "%s.%s" % (django_version.major, django_version.minor)
        self.config['django_version'] = django_version

