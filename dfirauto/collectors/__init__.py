"""DFIR-Auto forensic collectors."""

from dfirauto.collectors.base import BaseCollector
from dfirauto.collectors.evtx_collector import EvtxCollector
from dfirauto.collectors.filesystem_collector import FilesystemCollector
from dfirauto.collectors.network_collector import NetworkCollector
from dfirauto.collectors.persistence_collector import PersistenceCollector
from dfirauto.collectors.process_collector import ProcessCollector

__all__ = [
    "BaseCollector",
    "EvtxCollector",
    "FilesystemCollector",
    "NetworkCollector",
    "PersistenceCollector",
    "ProcessCollector",
]
