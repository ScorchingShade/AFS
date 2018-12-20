from __future__ import absolute_import, division, print_function, unicode_literals
import os
import json
import collections


def parse_filename(f):
    f = os.path.basename(f)
    return os.path.splitext(os.path.basename(f))

def file_is_lineup(f):
    name, extension = parse_filename(f)

    if name[0] in ('.', '_'):
        return False

    if not extension in ('.json'):
        return False

    return True

def ls(filter_function=None):
    if filter_function is None:
        filter_function = lambda lineup: True

    lineups = [parse_filename(f)[0] for f in os.listdir(os.path.join('fuse/lineups')) if file_is_lineup(f)]

    return filter(filter_function, lineups)

def get(lineup_name):
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'lineups', '%s.json') % lineup_name) as f:
        lineup = json.JSONDecoder(object_pairs_hook=collections.OrderedDict).decode(f.read())

    return lineup
