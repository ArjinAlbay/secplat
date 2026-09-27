from __future__ import annotations

import pytest

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.value_objects import TargetKind, TargetRef


def test_path_target_accepted() -> None:
    ref = TargetRef(kind=TargetKind.PATH, value="/srv/projects/app")
    assert ref.kind is TargetKind.PATH
    assert ref.value == "/srv/projects/app"


@pytest.mark.parametrize("value", ["app", "relative/path", "./app"])
def test_relative_path_rejected(value: str) -> None:
    with pytest.raises(InvalidTargetValue):
        TargetRef(kind=TargetKind.PATH, value=value)


def test_path_with_null_byte_rejected() -> None:
    with pytest.raises(InvalidTargetValue):
        TargetRef(kind=TargetKind.PATH, value="/srv/projects/ap\x00p")
