import pkgutil

from honeygrove import services

"""
Dynamic import of all Classes in package
"""

package = services
prefix = package.__name__ + "."

for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, prefix):
    if not ispkg:
        __import__(modname)
