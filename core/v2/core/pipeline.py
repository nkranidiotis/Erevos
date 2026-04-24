from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Iterable, List

from core.v2.models.contracts import AnalysisContext


class Stage(Protocol):
    name: str

    def run(self, ctx: AnalysisContext) -> None: ...


@dataclass
class AnalysisPipeline:
    """Minimal orchestrator for PE Static Analysis 2.0."""

    stages: List[Stage] = field(default_factory=list)

    def extend(self, stages: Iterable[Stage]) -> None:
        self.stages.extend(stages)

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        for stage in self.stages:
            ctx.add_log("stage_start", {"stage": stage.name})
            stage.run(ctx)
            ctx.add_log("stage_end", {"stage": stage.name})
        return ctx
