"""The common dictionary (spec §5, dict/common-1.zdict of the spec repository): trained on open
conversations, the same for everyone. A device that has it compresses with it until it has
trained its own for a device: node.add_dict(COMMON_DICT)."""
from importlib.resources import files

COMMON_DICT: bytes = files(__package__).joinpath("common-1.zdict").read_bytes()
