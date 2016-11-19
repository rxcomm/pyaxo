try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import versioneer
from glob import glob


BASE_DIRECTORY = '/usr/share/pyaxo'

setup(
    name='pyaxo',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Python implementation of the Axolotl ratchet protocol',
    author='David R. Andersen',
    author_email='k0rx@RXcomm.net',
    url='https://github.com/rxcomm/pyaxo',
    py_modules=[
        'pyaxo'
    ],
    install_requires=[
        'passlib>=1.6.1',
        'pynacl>=1.0.1',
    ],
    data_files=[
        (BASE_DIRECTORY + '/examples', glob('examples/*')),
        (BASE_DIRECTORY + '/tests', glob('tests/*')),
        (BASE_DIRECTORY + '/utilities', glob('utilities/*')),
        (BASE_DIRECTORY, ['COPYING']),
        (BASE_DIRECTORY, ['README.rst']),
    ],
)
