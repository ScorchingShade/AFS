import pytest

@pytest.fixture
def pinboard():
    from fuse.utils import pinboards
    return pinboards.Pinboard()

def test_post_and_get_pin(pinboard):
    pinboard.post_pin('test_pin', 'test_message')
    (pin_id, pin), = pinboard.get(exclude=[])

    assert pin.label == 'test_pin'
    assert pin.message == 'test_message'

def test_exclude_pins(pinboard):
    test_data = [
        ('test_pin_a', 'test_message_a'),
        ('test_pin_b', 'test_message_b'),
        ('test_pin_c', 'test_message_c'),
        ('test_pin_d', 'test_message_d'),
        ('test_pin_e', 'test_message_e'),
    ]

    exclude = [pinboard.post_pin(label, message) for label, message in test_data]

    (pin_id_d, pin_d), (pin_id_e, pin_e) = pinboard.get(exclude=exclude[:3])

    assert pin_d.label == 'test_pin_d'
    assert pin_d.message == 'test_message_d'

    assert pin_e.label == 'test_pin_e'
    assert pin_e.message == 'test_message_e'

