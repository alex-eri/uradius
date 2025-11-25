from setuptools import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize
from glob import glob
import sys
import os
import re
import ssl
from io import open


if sys.platform == "win32":
    openssl_base_version = re.search(r"^OpenSSL ([0-9.]+)", ssl.OPENSSL_VERSION).group(1)
    if openssl_base_version.startswith("3.0"):
        openssl_version = "3.0.11"

    openssl_dir = os.path.join("openssl", openssl_version, "amd64")

    ssl_include_dirs = [os.path.join(openssl_dir, "include")]

    ssl_library_dirs = [openssl_dir]
    ssl_libraries = ["libssl", "libcrypto"]

else:
    ssl_include_dirs = []
    ssl_library_dirs = []
    ssl_libraries = ["ssl", "crypto"]


# from distutils.command.build_ext import build_ext

from datetime import datetime


ext_modules = list(cythonize(
    glob('radius/*.pyx') + glob('radius/mschap/*.py'),
    compiler_directives={'language_level': "3"}
))
ext_modules.append(
    Extension(
        "radius._sslkeylog", ["radius/_sslkeylog.c"],
        libraries=ssl_libraries,
        include_dirs=ssl_include_dirs,
        library_dirs=ssl_library_dirs
    )
)
setup(
    name="URadius",
    version=datetime.now().strftime('%Y.%m.%d'),

    install_requires=[
         'pycryptodome', 'aenum', 'asyncache', 'cryptography'
    ],
    packages=['radius', 'radius.eap'],
    package_data={'radius': ['dictionary/dict*']},

    ext_modules=ext_modules,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': ['uradius = radius.server:run']
    }
)

# from subprocess import call
# call([sys.executable, '-m', 'radius', '--tls-generate'], cwd='/')
