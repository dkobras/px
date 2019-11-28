#!/usr/bin/pytest-3

import requests
import sys
import urllib3

def get(url):
    proxy = 'http://127.0.0.1:3128'
    proxies = { 'http': proxy, 'https': proxy }

    urllib3.disable_warnings()

    return requests.get(url, proxies=proxies, verify=False)

def test_direct():
    r = get('http://ntlmserver-http')
    assert r.status_code == 200
    assert 'OK' in r.content.decode('utf8')
    assert 'via:' not in r.content.decode('utf8')

def test_ntlm():
    r = get('http://ntlmserver-http.example.com')
    assert r.status_code == 200
    assert 'OK' in r.content.decode('utf8')
    via = [line[5:] for line in r.content.decode('utf8').splitlines() if line.startswith('via: ')]
    assert 'squid-ntlm' in ' '.join(via)

def test_spnego_http():
    r = get('http://testserver-http.example.com')
    assert r.status_code == 200
    assert 'OK' in r.content.decode('utf8')
    via = [line[5:] for line in r.content.decode('utf8').splitlines() if line.startswith('via: ')]
    assert 'squid-spnego' in ' '.join(via)

def test_spnego_https():
    r = get('https://testserver-https.example.com')
    assert r.status_code == 200
    assert 'OK' in r.content.decode('utf8')

