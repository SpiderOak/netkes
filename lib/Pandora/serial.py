'''! @package Pandora.serial
Abstract away from the "latest hotness" in serialization

Since we aren't sure that we will forever stick with cerealizer,
having already once switched from pickle, we've created this module to
centralize our implementation.

Use register to note classes which are safe to serialize.

@complete OK 20080102 bryon
'''

import sys
from itertools import chain
import Crypto.PublicKey.RSA

# Cerealizer has mostly the same interface as pickle, so we just
# import it's functions here.

from cerealizer import dump, dumps, load, loads, register, register_alias
from cerealizer import NotCerealizerFileError, NonCerealizableObjectError, \
    EndOfFile

NotSerializerFileError = NotCerealizerFileError
NotSerializableObjectError = NotCerealizerFileError

cryptoclass = ('Crypto.PublicKey.RSA',  'RSAobj' )

if hasattr(Crypto.PublicKey.RSA,'RSAImplementation'):
    cryptoclass = ('Crypto.PublicKey.RSA', '_RSAobj')

## Our serializable classes/modules

## 20110725 MattE- Shortened from the original source, no other use of
## Pandora libs means no need to register other Pandora types here.
known = [
    cryptoclass ,
    ]

aliases = None

if not hasattr(Crypto.PublicKey.RSA,'RSAImplementation'):
    aliases = {
        'Crypto.PublicKey.RSA': (
            ('RSAobj', 'RSAobj_c'),
            )
        }
else:
    aliases = {
        'Crypto.PublicKey.RSA': (
            ('_RSAobj', 'RSAobj'),
            ('_RSAobj', 'RSAobj_c'),
            )
        }

_already_called = False
def register_all(extras = []):
    """! Register our known serializables.

    @param extras extra class/mod names to allow serialization
    @good OK 20080102 bryon
    """
    global _already_called
    if _already_called:
        return
    _already_called = True
    for module_name, class_names in chain(known, extras):

        before = sys.modules

        if type(class_names) == str:
            class_names = [ class_names ]


        module = __import__(module_name, globals(), locals(),
                            class_names)
        for class_name in class_names:
            clas = getattr(module, class_name)
            # this has to be ugly to maintain backwards crypto compatibility
            # internal classnames that cerealizer picks up/picked up on changed from PyCrypto 2.0.1 -> 2.1.0
            # as such we need to alias both the generated and read it classnames.
            # if any more changes need to happen here, or this gets called more than once per process
            # or we start multiprocessing for whatever reason, register_all will need a refactoring.
            if class_name == '_RSAobj':
                register(clas, classname = 'Crypto.PublicKey.RSA.RSAobj')
            else:
                register(clas)

        if module_name in aliases:
            for alias in aliases[module_name]:
                clas = getattr(module,alias[0])
                register_alias(clas, '.'.join((module_name, alias[1])))

        sys.modules = before

if not hasattr(Crypto.PublicKey.RSA,'RSAImplementation'):
    Crypto.PublicKey.RSA.construct = Crypto.PublicKey.RSA.construct_py
    Crypto.PublicKey.RSA.generate = Crypto.PublicKey.RSA.generate_py


    __all__ = [dump, dumps, load, loads, register, register_all,
        NotCerealizerFileError]
