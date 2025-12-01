"""
Test cases for IP Information Lookup Tool
"""
import pytest
from unittest.mock import patch, MagicMock
import ipaddress
import os
import sys

# Import functions from your main script
# Assuming your main script is named 'ip_lookup.py'
from ip_lookup import is_valid_ip, normalize_data, clear_screen


def test_is_valid_ip_with_valid_ipv4():
    """Test that valid IPv4 addresses are recognized."""
    assert is_valid_ip("8.8.8.8") == True
    assert is_valid_ip("192.168.1.1") == True


def test_is_valid_ip_with_valid_ipv6():
    """Test that valid IPv6 addresses are recognized."""
    assert is_valid_ip("2001:4860:4860::8888") == True


def test_is_valid_ip_with_invalid_input():
    """Test that invalid IP strings are rejected."""
    assert is_valid_ip("not_an_ip") == False
    assert is_valid_ip("999.999.999.999") == False
    assert is_valid_ip("") == False


def test_normalize_data_ipapi():
    """Test data normalization from ipapi.co provider."""
    raw_data = {
        'ip': '8.8.8.8',
        'version': 'IPv4',
        'org': 'Google LLC',
        'asn': 'AS15169',
        'city': 'Mountain View',
        'region': 'California',
        'country_code': 'US'
    }
    result = normalize_data(raw_data, 'ipapi.co')
    assert result['ip'] == '8.8.8.8'
    assert result['version'] == 'IPv4'
    assert result['isp'] == 'Google LLC'


def test_normalize_data_ipinfo():
    """Test data normalization from ipinfo.io provider."""
    raw_data = {
        'ip': '1.1.1.1',
        'org': 'AS13335 Cloudflare, Inc.',
        'city': 'Los Angeles',
        'region': 'California',
        'country': 'US'
    }
    result = normalize_data(raw_data, 'ipinfo.io')
    assert result['ip'] == '1.1.1.1'
    assert result['asn'] == 'AS13335'"""
Test cases for IP Information Lookup Tool
"""
import pytest
from unittest.mock import patch
from ip_lookup import is_valid_ip, normalize_data, clear_screen


def test_is_valid_ip_with_valid_ipv4():
    """Test that valid IPv4 addresses are recognized."""
    assert is_valid_ip("8.8.8.8") == True
    assert is_valid_ip("192.168.1.1") == True


def test_is_valid_ip_with_valid_ipv6():
    """Test that valid IPv6 addresses are recognized."""
    assert is_valid_ip("2001:4860:4860::8888") == True


def test_is_valid_ip_with_invalid_input():
    """Test that invalid IP strings are rejected."""
    assert is_valid_ip("not_an_ip") == False
    assert is_valid_ip("999.999.999.999") == False
    assert is_valid_ip("") == False


def test_normalize_data_ipapi():
    """Test data normalization from ipapi.co provider."""
    raw_data = {
        'ip': '8.8.8.8',
        'version': 'IPv4',
        'org': 'Google LLC',
        'asn': 'AS15169',
        'city': 'Mountain View',
        'region': 'California',
        'country_code': 'US'
    }
    result = normalize_data(raw_data, 'ipapi.co')
    assert result['ip'] == '8.8.8.8'
    assert result['version'] == 'IPv4'
    assert result['isp'] == 'Google LLC'


def test_normalize_data_ipinfo():
    """Test data normalization from ipinfo.io provider."""
    raw_data = {
        'ip': '1.1.1.1',
        'org': 'AS13335 Cloudflare, Inc.',
        'city': 'Los Angeles',
        'region': 'California',
        'country': 'US'
    }
    result = normalize_data(raw_data, 'ipinfo.io')
    assert result['ip'] == '1.1.1.1'
    assert result['asn'] == 'AS13335'
    assert result['isp'] == 'Cloudflare, Inc.'


def test_clear_screen_function_exists():
    """Test that the clear_screen function exists and is callable."""
    assert callable(clear_screen)

    assert result['isp'] == 'Cloudflare, Inc.'


def test_clear_screen_function_exists():
    """Test that the clear_screen function exists and is callable."""
    assert callable(clear_screen)


@patch('os.system')
def test_clear_screen_calls_correct_command(mock_system):
    """Test that clear_screen calls the appropriate OS command."""
    clear_screen()
    # Should call either 'cls' (Windows) or 'clear' (Unix/Mac)
    mock_system.assert_called_once()
