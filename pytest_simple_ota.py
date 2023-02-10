# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Unlicense OR CC0-1.0
import http.server
import multiprocessing
import os
import ssl
import sys
from typing import Tuple

import pexpect
import pytest
#from common_test_methods import get_env_config_variable, get_host_ip4_by_dest_ip
from pytest_embedded import Dut

server_cert = '-----BEGIN CERTIFICATE-----\n' \
'MIIDlzCCAn+gAwIBAgIULDTHXFEBX3+mTdpf2a5AMIS7IuowDQYJKoZIhvcNAQEL\n' \
'BQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n' \
'GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLMTAuMTAuMC4xMzIw\n' \
'HhcNMjMwMjA2MDgxNDE1WhcNMjQwMjA2MDgxNDE1WjBbMQswCQYDVQQGEwJBVTET\n' \
'MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ\n' \
'dHkgTHRkMRQwEgYDVQQDDAsxMC4xMC4wLjEzMjCCASIwDQYJKoZIhvcNAQEBBQAD\n' \
'ggEPADCCAQoCggEBAKNmGN4j9KnfNGp46ro0RB2O1Ian6FEKyzs4t3sAR0pZGfvh\n' \
'2Oo/6FLAR+/Q9rb+gV5AM2/zpC9Ub+VH8OCerUQYbBbtvU9TtGULfe6McLd70bw/\n' \
'ZVni5wnXlmqByEx4TcCrNBWxUPzPJN9xcAE1lnO5e2NAV36EXWI8qLYX/XmL2bNV\n' \
'ukvbnw9KGN3wYvE5Ye+1xEJfKzecJHZ4AT2NR04+ftHJAiqlhjKBGeT+OzJiHwQh\n' \
'vUl6k9BeV6sV9vtsv+0hC7InCdrLl4wxG56smsDDRTnT/umpmUCG8DhLRS8nL/L/\n' \
'kbfHLwDa+phI+49BMJzV8f+ARRq1BHsDWWXCey8CAwEAAaNTMFEwHQYDVR0OBBYE\n' \
'FAhZB6kDY1Isa+BFE7mjc0RujvjgMB8GA1UdIwQYMBaAFAhZB6kDY1Isa+BFE7mj\n' \
'c0RujvjgMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJB72F1a\n' \
'DMTg+7H0XYfv2ufRmLqXGIS6mXYftkcfV9tJSb/2xcH3J+K6o6s+veDu+AKuEted\n' \
'R9yvSZZhZqc6R+9f4cIKbNlqEmGPRAN/cddjO5605V0HPfiBKJb3OTKHk3Ih51ws\n' \
'x4lSrsv65ZbIrAFnntq+BBLmqZwnZInWpSJNG+/hCBpD8F7GzqB+/asAF0OH9HPR\n' \
'htQg3GO73SEGfoOf0IXIBUQ1+VszJG/1syMwlOxRBsWoUMm0TMW6ARIVricewt0s\n' \
'ZlXSwnDzKw4KDQzjAGf65WyqD8w1nmUq/9g9HicBblb+E0radPv3m2JKRDF2WSgn\n' \
'EYR0XnX2+oLjgiw=\n' \
              '-----END CERTIFICATE-----\n'

server_key = '-----BEGIN PRIVATE KEY-----\n'\
'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjZhjeI/Sp3zRq\n' \
'eOq6NEQdjtSGp+hRCss7OLd7AEdKWRn74djqP+hSwEfv0Pa2/oFeQDNv86QvVG/l\n' \
'R/Dgnq1EGGwW7b1PU7RlC33ujHC3e9G8P2VZ4ucJ15ZqgchMeE3AqzQVsVD8zyTf\n' \
'cXABNZZzuXtjQFd+hF1iPKi2F/15i9mzVbpL258PShjd8GLxOWHvtcRCXys3nCR2\n' \
'eAE9jUdOPn7RyQIqpYYygRnk/jsyYh8EIb1JepPQXlerFfb7bL/tIQuyJwnay5eM\n' \
'MRuerJrAw0U50/7pqZlAhvA4S0UvJy/y/5G3xy8A2vqYSPuPQTCc1fH/gEUatQR7\n' \
'A1llwnsvAgMBAAECggEAP+yGWAmLAxYOZIUPl28xIrspC9EOgv4NCgsjRNyUB1Ma\n' \
'Zj8x5FrCIfWVbw26J1cj92J4fRi9J8MJz5I4eze4o0ZGqyWxBSLDFTDMwJFy22V2\n' \
'ZQYMOYEaT/BmqR5C5R+/k1unEcF/5JeJXlz7q41yYa2zxt16HUXdXrxKaIq0IGNk\n' \
'gWWBXLXdE6Waz/cUJaxhIosvWujp8zoYG2Ly/Nqb5j1uXMj3xgDF+nCjt0oRm9nG\n' \
'+GPL+hDaQQdD7gBq+7HuolvmvlI2PjW5AnPb8qK6vVYqPoHr7vqxW8YIHgHVM3jC\n' \
'8o+R4/gevJbUYspoJvZVEdAKTnFjaz1ij6e/O3OdwQKBgQC+LvrDAo8yLUT7tRdY\n' \
'c7WmB84RZk1NGVasLkZgOMNMtPWkK/zn3M00BK1h7nsliV/gjKiz3BXnkcL1jF8R\n' \
'inWeEtYogKS0n5J23OV3s1jAWsmYo0o10XHXXwM3LPfU2tp2UJHD3/yIKGe/byyu\n' \
'aWEIpjIYeDqrcf82KLglkoQA4QKBgQDb8ir90HC9+/aw9/u8q9vU6yWdh/w2SFOs\n' \
'xGn/1hL9edRGkjGfXJZKssIiQv9n/t02U9HHKN6Nz+aCXkEQ37zJryIHWJmaEn7b\n' \
'97n33c0nkfMCLlC6YMVg0vkJAxQ5FySsBaHzOwfC9zAIoaEHnDXim47FSM9ht8yV\n' \
'TtNyLZ4uDwKBgEQDLwBAUQ9jqxDM8T1bm/F1Rxdn22sgDaPjpJ1Sj11GNbZxWK9e\n' \
'gjABIDQugfGpkBUQmGBB6791nCAOBA2U030lRVsUrlI94rYJRzKoe6vGi+O/OZHH\n' \
'hgu8Wb0IotSHM6suIwLGflv+/yMx0evJmb7rGG0xyeF4Egm/RCODoxthAoGBAMlq\n' \
'y9QDvjs9Mnx9nBr7hyVE8f2BOoa7VWUxuaB/+oQFvU+jMa4uq7NcYEvf7uTdkNbf\n' \
'i4xG8QgNC5r3lb5OJiTMLO1tRbzCk0n9YmCKzgUestucbnE/jYFNsqF+IFbnyr19\n' \
'qwGDXWg91c8RtNWzR+VtbyFbvA5QsxlIRnqZK/IhAoGAf0qpQGWS5ANGKeu19Z3q\n' \
'snc1Y2/vFNIwcniJ15PlwSlogmBb40UUI72LHE2QvbaoO0SJ4PpL0mRuILAGMHtF\n' \
'U30MQMEUhLLs8D83djeY3FEqN9g6BQ/48Qd/4AVP9Ewv66BeOwyofriEU97l5WZa\n' \
'MYDSJO6VYjpGNM8Kv9WcvoY=\n' \
             '-----END PRIVATE KEY-----\n'


def start_https_server(ota_image_dir: str, server_ip: str, server_port: int, server_file: str = None, key_file: str = None) -> None:
    os.chdir(ota_image_dir)

    if server_file is None:
        server_file = os.path.join(ota_image_dir, 'server_cert.pem')
        cert_file_handle = open(server_file, 'w+')
        cert_file_handle.write(server_cert)
        cert_file_handle.close()

    if key_file is None:
        key_file = os.path.join(ota_image_dir, 'server_key.pem')
        key_file_handle = open('server_key.pem', 'w+')
        key_file_handle.write(server_key)
        key_file_handle.close()

    httpd = http.server.HTTPServer((server_ip, server_port), http.server.SimpleHTTPRequestHandler)

    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile=key_file,
                                   certfile=server_file, server_side=True)
    httpd.serve_forever()


def check_sha256(sha256_expected: str, sha256_reported: str) -> None:
    print('sha256_expected: %s' % (sha256_expected))
    print('sha256_reported: %s' % (sha256_reported))
    if sha256_expected not in sha256_reported:
        raise ValueError('SHA256 mismatch')
    else:
        print('SHA256 expected and reported are the same')


def calc_all_sha256(dut: Dut) -> Tuple[str, str]:
    bootloader_path = os.path.join(dut.app.binary_path, 'bootloader', 'bootloader.bin')
    sha256_bootloader = dut.app.get_sha256(bootloader_path)

    app_path = os.path.join(dut.app.binary_path, 'simple_ota.bin')
    sha256_app = dut.app.get_sha256(app_path)

    return str(sha256_bootloader), str(sha256_app)


@pytest.mark.esp32
@pytest.mark.esp32c3
@pytest.mark.esp32s2
@pytest.mark.esp32s3
@pytest.mark.wifi_high_traffic
def test_examples_protocol_simple_ota_example(dut: Dut) -> None:
    """
    steps: |
      1. join AP/Ethernet
      2. Fetch OTA image over HTTPS
      3. Reboot with the new OTA image
    """
    sha256_bootloader, sha256_app = calc_all_sha256(dut)
    # Start server
    thread1 = multiprocessing.Process(target=start_https_server, args=(dut.app.binary_path, '0.0.0.0', 8000))
    thread1.daemon = True
    thread1.start()
    try:
        # start test
        dut.expect('Loaded app from partition at offset 0x10000', timeout=30)
        check_sha256(sha256_bootloader, str(dut.expect(r'SHA-256 for bootloader:\s+([a-f0-9]){64}')[0]))
        check_sha256(sha256_app, str(dut.expect(r'SHA-256 for current firmware:\s+([a-f0-9]){64}')[0]))
        # Parse IP address of STA
        if dut.app.sdkconfig.get('EXAMPLE_WIFI_SSID_PWD_FROM_STDIN') is True:
            env_name = 'wifi_high_traffic'
            dut.expect('Please input ssid password:')
            ap_ssid = get_env_config_variable(env_name, 'ap_ssid')
            ap_password = get_env_config_variable(env_name, 'ap_password')
            dut.write(f'{ap_ssid} {ap_password}')
        try:
            ip_address = dut.expect(r'IPv4 address: (\d+\.\d+\.\d+\.\d+)[^\d]', timeout=30)[1].decode()
            print('Connected to AP/Ethernet with IP: {}'.format(ip_address))
        except pexpect.exceptions.TIMEOUT:
            raise ValueError('ENV_TEST_FAILURE: Cannot connect to AP/Ethernet')
        host_ip = get_host_ip4_by_dest_ip(ip_address)

        dut.expect('Starting OTA example task', timeout=30)
        print('writing to device: {}'.format('https://' + host_ip + ':8000/simple_ota.bin'))
        dut.write('https://' + host_ip + ':8000/simple_ota.bin')
        dut.expect('OTA Succeed, Rebooting...', timeout=60)
        # after reboot
        dut.expect('Loaded app from partition at offset 0x110000', timeout=30)
        dut.expect('OTA example app_main start', timeout=10)
    finally:
        thread1.terminate()


@pytest.mark.esp32
@pytest.mark.esp32c3
@pytest.mark.esp32s2
@pytest.mark.esp32s3
@pytest.mark.ethernet_ota
@pytest.mark.parametrize('config', ['spiram',], indirect=True)
def test_examples_protocol_simple_ota_example_ethernet_with_spiram_config(dut: Dut) -> None:
    """
    steps: |
      1. join AP/Ethernet
      2. Fetch OTA image over HTTPS
      3. Reboot with the new OTA image
    """
    # Start server
    thread1 = multiprocessing.Process(target=start_https_server, args=(dut.app.binary_path, '0.0.0.0', 8000))
    thread1.daemon = True
    thread1.start()
    try:
        # start test
        dut.expect('Loaded app from partition at offset 0x10000', timeout=30)
        try:
            ip_address = dut.expect(r'IPv4 address: (\d+\.\d+\.\d+\.\d+)[^\d]', timeout=30)[1].decode()
            print('Connected to AP/Ethernet with IP: {}'.format(ip_address))
        except pexpect.exceptions.TIMEOUT:
            raise ValueError('ENV_TEST_FAILURE: Cannot connect to AP/Ethernet')
        host_ip = get_host_ip4_by_dest_ip(ip_address)

        dut.expect('Starting OTA example task', timeout=30)
        print('writing to device: {}'.format('https://' + host_ip + ':8000/simple_ota.bin'))
        dut.write('https://' + host_ip + ':8000/simple_ota.bin')
        dut.expect('OTA Succeed, Rebooting...', timeout=60)
        # after reboot
        dut.expect('Loaded app from partition at offset 0x110000', timeout=30)
        dut.expect('OTA example app_main start', timeout=10)
    finally:
        thread1.terminate()


@pytest.mark.esp32
@pytest.mark.esp32c3
@pytest.mark.flash_encryption_wifi_high_traffic
@pytest.mark.nightly_run
@pytest.mark.parametrize('config', ['flash_enc_wifi',], indirect=True)
@pytest.mark.parametrize('skip_autoflash', ['y'], indirect=True)
def test_examples_protocol_simple_ota_example_with_flash_encryption_wifi(dut: Dut) -> None:
    """
    steps: |
      1. join AP/Ethernet
      2. Fetch OTA image over HTTPS
      3. Reboot with the new OTA image
    """
    # start test
    # Erase flash
    dut.serial.erase_flash()
    dut.serial.flash()
    # Start server
    thread1 = multiprocessing.Process(target=start_https_server, args=(dut.app.binary_path, '0.0.0.0', 8000))
    thread1.daemon = True
    thread1.start()
    try:
        dut.expect('Loaded app from partition at offset 0x20000', timeout=30)
        dut.expect('Flash encryption mode is DEVELOPMENT', timeout=10)
        # Parse IP address of STA
        if dut.app.sdkconfig.get('EXAMPLE_WIFI_SSID_PWD_FROM_STDIN') is True:
            env_name = 'flash_encryption_wifi_high_traffic'
            dut.expect('Please input ssid password:')
            ap_ssid = get_env_config_variable(env_name, 'ap_ssid')
            ap_password = get_env_config_variable(env_name, 'ap_password')
            dut.write(f'{ap_ssid} {ap_password}')
        try:
            ip_address = dut.expect(r'IPv4 address: (\d+\.\d+\.\d+\.\d+)[^\d]', timeout=30)[1].decode()
            print('Connected to AP/Ethernet with IP: {}'.format(ip_address))
        except pexpect.exceptions.TIMEOUT:
            raise ValueError('ENV_TEST_FAILURE: Cannot connect to AP/Ethernet')
        host_ip = get_host_ip4_by_dest_ip(ip_address)

        dut.expect('Starting OTA example task', timeout=30)
        print('writing to device: {}'.format('https://' + host_ip + ':8000/simple_ota.bin'))
        dut.write('https://' + host_ip + ':8000/simple_ota.bin')
        dut.expect('OTA Succeed, Rebooting...', timeout=60)
        # after reboot
        dut.expect('Loaded app from partition at offset 0x120000', timeout=30)
        dut.expect('Flash encryption mode is DEVELOPMENT', timeout=10)
        dut.expect('OTA example app_main start', timeout=10)
    finally:
        thread1.terminate()


@pytest.mark.esp32
@pytest.mark.esp32c3
@pytest.mark.esp32s2
@pytest.mark.esp32s3
@pytest.mark.ethernet_ota
@pytest.mark.parametrize('config', ['on_update_no_sb_ecdsa',], indirect=True)
def test_examples_protocol_simple_ota_example_with_verify_app_signature_on_update_no_secure_boot_ecdsa(dut: Dut) -> None:
    """
    steps: |
      1. join AP/Ethernet
      2. Fetch OTA image over HTTPS
      3. Reboot with the new OTA image
    """
    sha256_bootloader, sha256_app = calc_all_sha256(dut)
    # Start server
    thread1 = multiprocessing.Process(target=start_https_server, args=(dut.app.binary_path, '0.0.0.0', 8000))
    thread1.daemon = True
    thread1.start()
    try:
        # start test
        dut.expect('Loaded app from partition at offset 0x20000', timeout=30)
        check_sha256(sha256_bootloader, str(dut.expect(r'SHA-256 for bootloader:\s+([a-f0-9]){64}')[0]))
        check_sha256(sha256_app, str(dut.expect(r'SHA-256 for current firmware:\s+([a-f0-9]){64}')[0]))
        try:
            ip_address = dut.expect(r'IPv4 address: (\d+\.\d+\.\d+\.\d+)[^\d]', timeout=30)[1].decode()
            print('Connected to AP/Ethernet with IP: {}'.format(ip_address))
        except pexpect.exceptions.TIMEOUT:
            raise ValueError('ENV_TEST_FAILURE: Cannot connect to AP/Ethernet')
        host_ip = get_host_ip4_by_dest_ip(ip_address)

        dut.expect('Starting OTA example task', timeout=30)
        print('writing to device: {}'.format('https://' + host_ip + ':8000/simple_ota.bin'))
        dut.write('https://' + host_ip + ':8000/simple_ota.bin')
        dut.expect('Writing to partition subtype 16 at offset 0x120000', timeout=20)
        dut.expect('Verifying image signature...', timeout=60)
        dut.expect('OTA Succeed, Rebooting...', timeout=60)
        # after reboot
        dut.expect('Loaded app from partition at offset 0x120000', timeout=20)
        dut.expect('OTA example app_main start', timeout=10)
    finally:
        thread1.terminate()


@pytest.mark.esp32
@pytest.mark.esp32c3
@pytest.mark.esp32s2
@pytest.mark.esp32s3
@pytest.mark.ethernet_ota
@pytest.mark.parametrize('config', ['on_update_no_sb_rsa',], indirect=True)
def test_examples_protocol_simple_ota_example_with_verify_app_signature_on_update_no_secure_boot_rsa(dut: Dut) -> None:
    """
    steps: |
      1. join AP/Ethernet
      2. Fetch OTA image over HTTPS
      3. Reboot with the new OTA image
    """
    sha256_bootloader, sha256_app = calc_all_sha256(dut)
    # Start server
    thread1 = multiprocessing.Process(target=start_https_server, args=(dut.app.binary_path, '0.0.0.0', 8000))
    thread1.daemon = True
    thread1.start()
    try:
        # start test
        dut.expect('Loaded app from partition at offset 0x20000', timeout=30)
        check_sha256(sha256_bootloader, str(dut.expect(r'SHA-256 for bootloader:\s+([a-f0-9]){64}')[0]))
        check_sha256(sha256_app, str(dut.expect(r'SHA-256 for current firmware:\s+([a-f0-9]){64}')[0]))
        try:
            ip_address = dut.expect(r'IPv4 address: (\d+\.\d+\.\d+\.\d+)[^\d]', timeout=30)[1].decode()
            print('Connected to AP/Ethernet with IP: {}'.format(ip_address))
        except pexpect.exceptions.TIMEOUT:
            raise ValueError('ENV_TEST_FAILURE: Cannot connect to AP/Ethernet')
        host_ip = get_host_ip4_by_dest_ip(ip_address)

        dut.expect('Starting OTA example task', timeout=30)
        print('writing to device: {}'.format('https://' + host_ip + ':8000/simple_ota.bin'))
        dut.write('https://' + host_ip + ':8000/simple_ota.bin')
        dut.expect('Writing to partition subtype 16 at offset 0x120000', timeout=20)
        dut.expect('Verifying image signature...', timeout=60)
        dut.expect('#0 app key digest == #0 trusted key digest', timeout=10)
        dut.expect('Verifying with RSA-PSS...', timeout=10)
        dut.expect('Signature verified successfully!', timeout=10)
        dut.expect('OTA Succeed, Rebooting...', timeout=60)
        # after reboot
        dut.expect('Loaded app from partition at offset 0x120000', timeout=20)
        dut.expect('OTA example app_main start', timeout=10)
    finally:
        thread1.terminate()


if __name__ == '__main__':
    if sys.argv[2:]:    # if two or more arguments provided:
        # Usage: example_test.py <image_dir> <server_port> [cert_di>]
        this_dir = os.path.dirname(os.path.realpath(__file__))
        bin_dir = os.path.join(this_dir, sys.argv[1])
        port = int(sys.argv[2])
        cert_dir = bin_dir if not sys.argv[3:] else os.path.join(this_dir, sys.argv[3])  # optional argument
        print('Starting HTTPS server at "https://:{}"'.format(port))
        start_https_server(bin_dir, '', port,
                           server_file=os.path.join(cert_dir, 'ca_cert.pem'),
                           key_file=os.path.join(cert_dir, 'ca_key.pem'))