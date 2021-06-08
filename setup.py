from setuptools import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize
from glob import glob

import os, sys


#from distutils.command.build_ext import build_ext

from datetime import datetime

setup(
    name="URadius",
    version="1." + datetime.now().strftime('%Y.%m.%d'),

    install_requires=[
          'sslkeylog', 'uvloop', 'pycrypto', 'aenum', 'asyncache'
    ],
    packages=['radius', 'radius.eap'],
    package_data={'radius': ['dictionary/dict*', 'certs/*.pem']},

    ext_modules = cythonize(
         glob('radius/*.pyx') + glob('radius/mschap/*.py'),
         compiler_directives={'language_level' : "3"}
    ),
    python_requires='>=3.6',
    entry_points={
        'console_scripts' : ['uradius = radius.server:run']
    }
)

# from subprocess import call
# call([sys.executable, '-m', 'radius', '--tls-generate'], cwd='/')


