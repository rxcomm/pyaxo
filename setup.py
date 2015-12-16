try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from glob import glob

BASE_DIRECTORY = '/usr/share/pyaxo'

setup(
    name='pyaxo',
    version='0.4.6',
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
