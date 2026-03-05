"""Abstract base class for all threat intelligence sources."""

from abc import ABC, abstractmethod
from threatscout.models.indicator import Indicator, IndicatorType
from threatscout.models.finding import Finding


class ThreatSource(ABC):
    """
    Base class for all threat intelligence sources.

    Each source declares which indicator types it supports, and implements
    `query()` to fetch and normalize results for a given indicator.
    """

    # Subclasses declare which indicator types they can handle
    supported_types: list[IndicatorType] = []

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supported_types

    @abstractmethod
    async def query(self, indicator: Indicator) -> Finding:
        """
        Query this source for the given indicator.

        Should always return a Finding — never raise. On error, return a
        Finding with error= set so the report can show partial results.
        """
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__
