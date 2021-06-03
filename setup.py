sources = """
radius/tlscert.py  radius/protocol.py   radius/handler.py     radius/constants.py
radius/server.py   radius/packet.py     radius/dictionary.py
""".split()

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize

#ext_modules = [Extension('radar', sources)]

setup(
    name="Radar",
    cmdclass={'build_ext': build_ext},
        install_requires=[
          'sslkeylog', 'uvloop', 'pycrypto', 'aenum', 'asyncache'
      ],

    ext_modules=cythonize(
        sources,
        compiler_directives={'language_level' : "3"}
    ),
    console_scripts = ['uradius = radius.server:run']
)
