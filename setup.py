from setuptools import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize
from glob import glob

import os, sys


#from distutils.command.build_ext import build_ext

from datetime import datetime


ext_modules = list(cythonize(
        glob('radius/*.pyx') + glob('radius/mschap/*.py'),
        compiler_directives={'language_level' : "3"}
))
ext_modules.append(
    Extension(
        "radius._sslkeylog", ["radius/_sslkeylog.c"],
        libraries = ["ssl", "crypto"]
    )
)
setup(
    name="URadius",
    version="1." + datetime.now().strftime('%Y.%m.%d'),

    install_requires=[
          'uvloop', 'pycryptodome', 'aenum', 'asyncache', 'cryptography'
    ],
    packages=['radius', 'radius.eap'],
    package_data={'radius': ['dictionary/dict*', 'certs/*.pem']},

    ext_modules = ext_modules,
    python_requires='>=3.7',
    entry_points={
        'console_scripts' : ['uradius = radius.server:run']
    }
)

# from subprocess import call
# call([sys.executable, '-m', 'radius', '--tls-generate'], cwd='/')


