#!/usr/bin/env python

import os
from lbrynet import __version__
from setuptools import setup, find_packages

# TODO: find a way to keep this in sync with requirements.txt
#
# Note though that this list is intentionally less restrictive than
# requirements.txt. This is only the libraries that are direct
# dependencies of the lbrynet library.  requirements.txt includes
# dependencies of dependencies and specific versions that we know
# all work together.
#
# See https://packaging.python.org/requirements/  and
# https://caremad.io/posts/2013/07/setup-vs-requirement/  for more details.
requires = [
    'aiohttp',
    'twisted[tls]',
    'appdirs',
    'distro',
    'base58',
    'envparse',
    'jsonrpc',
    'cryptography',
    'lbryschema',
    'torba',
    'miniupnpc',
    'txupnp==0.0.1a11',
    'pyyaml',
    'requests',
    'txJSON-RPC',
    'zope.interface',
    'treq',
    'docopt',
    'colorama==0.3.7',
    'six',
]

console_scripts = [
    'lbrynet-daemon = lbrynet.daemon.DaemonControl:start',
    'lbrynet-cli = lbrynet.daemon.DaemonCLI:main',
    'lbrynet-console = lbrynet.daemon.DaemonConsole:main'
]


def package_files(directory):
    for path, _, filenames in os.walk(directory):
        for filename in filenames:
            yield os.path.join('..', path, filename)


base_dir = os.path.abspath(os.path.dirname(__file__))
# Get the long description from the README file
with open(os.path.join(base_dir, 'README.md'), 'rb') as f:
    long_description = f.read().decode('utf-8')

setup(
    name="lbry",
    version=__version__,
    author="LBRY Inc.",
    author_email="hello@lbry.io",
    url="https://lbry.io",
    description="A decentralized media library and marketplace",
    long_description=long_description,
    keywords="lbry protocol media",
    license='MIT',
    python_requires='>=3.6',
    packages=find_packages(exclude=('tests',)),
    install_requires=requires,
    entry_points={'console_scripts': console_scripts},
    zip_safe=False,
    extras_require={
        'test': (
            'mock>=2.0,<3.0',
            'faker>=0.8,<1.0'
        )
    }
)
