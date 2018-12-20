from __future__ import absolute_import, division, print_function, unicode_literals
import semantic_version as semantic_version_module
import six
import os
import re

def not_none(value):
    """
    Value cannot be empty
    """
    return not value is None

def text(value):
    """
    Value can contain any readable character
    """
    return True

def variable_name(value):
    """
    Value can only contain alphanumerical characters and underscore
    """

    result = bool(re.match('^[a-zA-Z_$][a-zA-Z_$0-9]*$', value))

    if six.PY3:
        assert value.isidentifier() == result

    return result

def creatable_dir(value):
    """
    Directory must exist or be possible to create
    """
    if os.path.isdir(value):
        return True
    try:
        os.makedirs(value)
        return True
    except:
        return False

def writable_dir(value):
    """
    Must be writeable directory
    """
    return os.access(value, os.W_OK)

def empty_dir(value):
    """
    Must be en empty directory
    """
    return not os.listdir(value)

def semantic_version(value):
    """
    Value must be a valid semantic version
    """
    try:
        semantic_version_module.Version(value)
        return True
    except ValueError:
        return False
