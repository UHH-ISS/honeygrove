import pkgutil
from honeygrove.tests.testresources import serviceControllerTestPkg

"""
Dynamic import of all Clases of this package
"""

package = serviceControllerTestPkg
prefix = package.__name__ + "."

for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix):
    if not ispkg:
        __import__(modname)
