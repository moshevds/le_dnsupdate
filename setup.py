#!/usr/bin/env python
# coding=utf-8

from setuptools import setup

setup(name="letsencrypt_dnsupdate",
    version = "0.1",
    description = "Let`s Encrypt DNS Update (RFC 2136) Authenticator",
    author = "Môshe van der Sterre",
    author_email = "me@moshe.nl",
    url = None,
    packages = ['dnsupdate'],
    package_data = {'dnsupdate' : ['dnsupdate/*.py'] },
    long_description = None, 
    classifiers = ['Development Status :: 3 - Alpha'],

    zip_safe = False,
    install_requires = ['certbot', 'dnspython'],
    entry_points = {
        'certbot.plugins': [
            'dnsupdate = dnsupdate:Authenticator'
        ]
    }
)
