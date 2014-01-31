try:
    from setuptools import setup
except:
    from distutils.core import setup
import zipfile
import os
import pwd

setup(name='Axolotl',
      version='0.1',
      description='Python implementation of the Axolotl ratchet protocol',
      author='David R. Andersen',
      url='https://github.com/rxcomm/pyaxo',
      py_modules=['pyaxo'],
      install_requires=['python-gnupg >= 0.3.5'],
     )
