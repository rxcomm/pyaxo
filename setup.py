try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import platform
from glob import glob
from subprocess import call

distros = ('debian', 'ubuntu')
not_installed = True
if platform.linux_distribution()[0].lower() in distros:
    not_installed = call(['apt-get',  'install', '-y', 'python-dev'])
if not_installed:
    print 'Cannot verify if python-dev is installed. You might have to do it manually'

BASE_DIRECTORY = '/usr/share/pyaxo'

setup(
    name='pyaxo',
    version='0.3.6',
    description='Python implementation of the Axolotl ratchet protocol',
    author='David R. Andersen',
    author_email='k0rx@RXcomm.net',
    url='https://github.com/rxcomm/pyaxo',
    py_modules=[
        'pyaxo'
    ],
    install_requires=[
        'curve25519-donna',
        'passlib>=1.6.1',
        'python-gnupg>=0.3.5',
    ],
    dependency_links=[
        'git+https://github.com/agl/curve25519-donna.git#egg=curve25519-donna-1.2.1',
    ],
    data_files=[
        (BASE_DIRECTORY + '/examples', glob('examples/*')),
        (BASE_DIRECTORY + '/tests', glob('tests/*')),
        (BASE_DIRECTORY + '/utilities', glob('utilities/*')),
        (BASE_DIRECTORY, ['COPYING']),
        (BASE_DIRECTORY, ['README.rst']),
    ],
)
