"""EvalSeal — bind an evaluation result to the configuration that earned it."""

__version__ = "0.1.0"

from .address import addr_of, addr_of_text, short          # noqa: F401
from .canonical import PROFILES, canonicalize              # noqa: F401
from .manifest import build_manifest, load_config          # noqa: F401
from .receipt import issue, verify_against                 # noqa: F401
