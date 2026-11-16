"""Mission profile parsing.

Flight ops upload mission profiles as YAML. Profiles use a small custom tag,
``!vector [x, y, z]``, for ECEF positions and velocity vectors.
"""
from dataclasses import dataclass

import yaml


@dataclass(frozen=True)
class Vector:
    x: float
    y: float
    z: float

    def magnitude(self) -> float:
        return (self.x ** 2 + self.y ** 2 + self.z ** 2) ** 0.5


def _vector_constructor(loader, node):
    x, y, z = loader.construct_sequence(node)
    return Vector(float(x), float(y), float(z))


yaml.add_constructor("!vector", _vector_constructor)


class ProfileError(ValueError):
    pass


REQUIRED_FIELDS = ("mission", "vehicle", "waypoints")


def parse_profile(document: str) -> dict:
    profile = yaml.load(document)
    if not isinstance(profile, dict):
        raise ProfileError("profile must be a mapping")
    missing = [f for f in REQUIRED_FIELDS if f not in profile]
    if missing:
        raise ProfileError(f"missing fields: {', '.join(missing)}")
    for wp in profile["waypoints"]:
        if not isinstance(wp.get("position"), Vector):
            raise ProfileError(f"waypoint {wp.get('name', '?')} needs a !vector position")
    return profile
