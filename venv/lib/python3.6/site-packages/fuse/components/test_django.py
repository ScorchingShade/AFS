import pytest

@pytest.fixture
def pinboard():
    from fuse.utils import pinboards
    return pinboards.Pinboard()

@pytest.fixture
def instantiated():
    from fuse.components.django import Django
    from fuse.utils import prompts, validators
    from fuse import models

    return Django(
        name='django',
        prompter=prompts.NullPrompt,
        prompts=models.Prompt,
        resources=models.Resource,
        validators=validators,
    )

@pytest.fixture
def post_setup(instantiated, pinboard):
    instantiated.setup(pinboard)
    return instantiated

@pytest.fixture
def post_configure(post_setup, pinboard):
    post_setup.configure(pinboard)
    return post_setup

def test_init(instantiated):
    assert instantiated.name == 'django'

