try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import versioneer


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
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
)
