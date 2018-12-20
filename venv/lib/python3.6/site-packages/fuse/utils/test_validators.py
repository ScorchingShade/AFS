import pytest
import re

@pytest.fixture
def validators():
    from fuse.utils import validators
    return validators

def test_variable_name(validators):
    test_values = [
        ('asdf_qwerty1', True),
        ('1asdf_qwerty1', False),
        ('asdf_?qwerty1', False),
        ('asdf_ qwerty1', False),
    ]

    for test_value, expected_response in test_values:
        assert validators.variable_name(test_value) == expected_response
