import pyzephyrconnect
from pyzephyrconnect.exceptions import (
    ZephyrDataError,
    ZephyrError,
    ZephyrNotConnectedError,
    ZephyrWriteError,
)


def test_new_errors_are_catchable_as_the_base():
    """A consumer catching ZephyrError must catch everything the library
    raises. Bare RuntimeError/ValueError previously escaped that net."""
    for cls in (ZephyrNotConnectedError, ZephyrWriteError, ZephyrDataError):
        assert issubclass(cls, ZephyrError)


def test_new_errors_are_exported_from_the_package_root():
    for name in (
        "ZephyrNotConnectedError",
        "ZephyrWriteError",
        "ZephyrDataError",
    ):
        assert name in pyzephyrconnect.__all__
        assert hasattr(pyzephyrconnect, name)
