import pytest

from mixerscope.schema import Attr


@pytest.fixture
def attr() -> Attr:
    """A tier-1 observed provenance block citing the observation id 'obs-flow'."""
    return Attr(tier=0, basis="observed", sources=["obs-flow"])
