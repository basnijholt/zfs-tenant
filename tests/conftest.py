"""Options for explicitly requested built-artifact checks."""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Accept the exact wheel and zipapp under test."""
    parser.addoption("--wheel", help="wheel used to build the zipapp")
    parser.addoption("--pyz", help="zipapp to check outside the source checkout")
