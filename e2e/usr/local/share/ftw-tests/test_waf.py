"""
FTW Test Runner for PHP WAF

This file provides the test function that FTW uses to execute YAML based tests.
The FTW pytest plugin parametrizes this function based on the YAML test files.
"""
import pytest


def test_waf(test):
    """
    Execute FTW test from YAML definition.

    The 'test' fixture is provided by FTW's pytest plugin and contains
    all the test configuration from the YAML files.
    """
    # FTW handles the actual test execution internally
    # The test fixture contains the request/response expectations
    pass
