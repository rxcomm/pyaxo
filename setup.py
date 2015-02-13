try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import platform
from glob import glob
from subprocess import call

distro = platform.linux_distribution()[0].lower()
manager = {
    'debian': 'apt-get',
    'ubuntu': 'apt-get',
    'fedora': 'yum',
}
packages = {
    'python-dev': {'apt-get': 'python-dev', 'yum': 'python-devel'},
}
packages_string = ' '.join(packages.keys())
not_installed = True

if distro in manager:
    packages_list = []
    for package in packages:
        packages_list.append(packages[package][manager[distro]])
    not_installed = call([manager[distro], 'install', '-y'] + packages_list)
    packages_string = ' '.join(packages_list)

if not_installed:
    print 'Cannot verify if all/some of these packages are installed: ' + packages_string + '.You might have to do ' \
                                                                                            'it manually'

BASE_DIRECTORY = '/usr/share/pyaxo'

setup(
    name='pyaxo',
    version='0.3.8',
    description='Python implementation of the Axolotl ratchet protocol',
    author='David R. Andersen',
    author_email='k0rx@RXcomm.net',
    url='https://github.com/rxcomm/pyaxo',
    py_modules=[
        'pyaxo'
    ],
    install_requires=[
        'curve25519-donna>=1.3',
        'passlib>=1.6.1',
        'python-gnupg>=0.3.5',
    ],
    data_files=[
        (BASE_DIRECTORY + '/examples', glob('examples/*')),
        (BASE_DIRECTORY + '/tests', glob('tests/*')),
        (BASE_DIRECTORY + '/utilities', glob('utilities/*')),
        (BASE_DIRECTORY, ['COPYING']),
        (BASE_DIRECTORY, ['README.rst']),
    ],
)
