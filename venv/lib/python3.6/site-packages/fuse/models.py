from __future__ import absolute_import, division, print_function, unicode_literals
import six
from peewee import Model, CharField, OperationalError
from playhouse.sqlite_ext import SqliteExtDatabase
import datetime
import os
from jinja2 import Template

if six.PY2:
    from urllib2 import urlopen, HTTPError
else:
    from urllib.request import urlopen
    from urllib.error import HTTPError


db = SqliteExtDatabase(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fuse.db'))

class BaseModel(Model):
    class Meta:
        database = db

class Resource(BaseModel):
    identifier = CharField()
    component = CharField()
    from_version = CharField(null=True)
    to_version = CharField(null=True)
    target = CharField()
    content_source = CharField(null=True)

    def write(self, context):
        if self.content_source is None:
            content = ''
        else:
            content_source = self.content_source.format(**context)
            content = urlopen(content_source).read().decode('utf-8')
            content = Template(content).render(**context)

        target = self.target.format(**context)
        absolute_target = os.path.join(
            context['project_home'],
            target
        )

        try:
            os.makedirs(os.path.dirname(absolute_target))
        except OSError:
            pass

        with open(absolute_target, 'w') as fp:
            fp.write(content)


class Prompt(BaseModel):
    identifier = CharField()
    text = CharField(null=True)
    description = CharField(null=True)
    default = CharField(null=True)
    validators = CharField(null=True)
    options = CharField(null=True)


def data():
    resources = (
        {
            'identifier': 'settings',
            'component': 'django',
            'from_version': '1.10.1',
            'to_version': None,
            'target': '{project_name}/settings.py',
            'content_source': ('https://raw.githubusercontent.com/djan'
                               'go/django/{django_version}/django/conf'
                               '/project_template/project_name/setting'
                               's.py-tpl'),
        },
        {
            'identifier': 'init',
            'component': 'django',
            'from_version': '1.10.1',
            'to_version': None,
            'target': '{project_name}/__init__.py',
            'content_source': ('https://raw.githubusercontent.com/djan'
                               'go/django/{django_version}/django/conf'
                               '/project_template/project_name/__init_'
                               '_.py-tpl'),
        },
        {
            'identifier': 'urls',
            'component': 'django',
            'from_version': '1.10.1',
            'to_version': None,
            'target': '{project_name}/urls.py',
            'content_source': ('https://raw.githubusercontent.com/djan'
                               'go/django/{django_version}/django/conf'
                               '/project_template/project_name/urls.py'
                               '-tpl'),
        },
        {
            'identifier': 'wsgi',
            'component': 'django',
            'from_version': '1.10.1',
            'to_version': None,
            'target': '{project_name}/wsgi.py',
            'content_source': ('https://raw.githubusercontent.com/djan'
                               'go/django/{django_version}/django/conf'
                               '/project_template/project_name/wsgi.py'
                               '-tpl'),
        },
        {
            'identifier': 'manage',
            'component': 'django',
            'from_version': '1.10.1',
            'to_version': None,
            'target': 'manage.py',
            'content_source': ('https://raw.githubusercontent.com/djan'
                               'go/django/{django_version}/django/conf'
                               '/project_template/manage.py-tpl'),
        },
        {
            'identifier': 'requirements',
            'component': 'pip',
            'from_version': None,
            'to_version': None,
            'target': 'requirements.txt',
            'content_source': None,
        },
        )

    for resource in resources:
        Resource.create(**resource)

    prompts = (
        {
            'identifier': 'project_name',
            'text': "Project Name",
            'description': None,
            'default': None,
            'validators': None,
            'options': None,
        },
        {
            'identifier': 'project_slug',
            'text': "Project Slug",
            'description': None,
            'default': None,
            'validators': 'variable_name',
            'options': None,
        },
        {
            'identifier': 'semantic_version',
            'text': "Version (semantic)",
            'description': None,
            'default': None,
            'validators': 'semantic_version',
            'options': None,
        },
        {
            'identifier': 'directory',
            'text': "Directory",
            'description': None,
            'default': None,
            'validators': 'creatable_dir,writable_dir,empty_dir',
            'options': None,
        },
    )

    for prompt in prompts:
        Prompt.create(**prompt)

