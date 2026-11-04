from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Tuple


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NON_CONVERGENT = "non_convergent"


@dataclass(frozen=True)
class AnalysisDiagnostic:
    code: str
    message: str
    retryable: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class AnalysisResult:
    status: AnalysisStatus
    results: Tuple[Any, ...] = ()
    diagnostics: Tuple[AnalysisDiagnostic, ...] = ()
    coverage: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self):
        return self.status in {AnalysisStatus.COMPLETE, AnalysisStatus.PARTIAL}

    @property
    def evidence(self):
        return list(self.results)

    @classmethod
    def complete(cls, results: Iterable[Any] = (), **kwargs):
        return cls(AnalysisStatus.COMPLETE, tuple(results), **kwargs)

    @classmethod
    def partial(cls, results: Iterable[Any] = (), **kwargs):
        return cls(AnalysisStatus.PARTIAL, tuple(results), **kwargs)

    @classmethod
    def unsupported(cls, code: str, message: str, **kwargs):
        return cls(
            AnalysisStatus.UNSUPPORTED,
            diagnostics=(AnalysisDiagnostic(code, message),),
            **kwargs,
        )

    @classmethod
    def failed(cls, code: str, message: str, *, retryable: bool = False, **kwargs):
        return cls(
            AnalysisStatus.FAILED,
            diagnostics=(AnalysisDiagnostic(code, message, retryable=retryable),),
            **kwargs,
        )

    def to_dict(self):
        return {
            "status": self.status.value,
            "results": list(self.results),
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
            "coverage": dict(self.coverage),
            "provenance": dict(self.provenance),
            "resources": dict(self.resources),
        }
