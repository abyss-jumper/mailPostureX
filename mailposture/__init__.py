"""mailposture: audit email authentication and transport security."""

__version__ = "0.1.0"

from .checks import audit  # noqa: F401
from .doh import DoHResolver, StaticResolver  # noqa: F401
