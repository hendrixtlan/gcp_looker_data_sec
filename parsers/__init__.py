"""
Importa todos los módulos de parsers para que el decorador @register se ejecute.
ORDEN: no importa el orden de import, los parsers se ordenan por `priority`.
"""
from .base import parse_log, get_parsers, ParsedLog, BaseParser

# Imports con efecto secundario: registran parsers
from . import fortinet      # noqa: F401
from . import paloalto      # noqa: F401
from . import modsecurity   # noqa: F401
from . import generic_cef   # noqa: F401
from . import _others       # noqa: F401

__all__ = ["parse_log", "get_parsers", "ParsedLog", "BaseParser"]
