from dataclasses import dataclass, asdict
from typing import DefaultDict, Dict

from tuf.api.metadata import Key


@dataclass
class TUFKeys:
    keys: Dict[str, Key]    
    type: str = "securesystemslib"

    def to_dict(self):
        return asdict(self)
