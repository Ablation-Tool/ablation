"""
llm_analyst — LLM-assisted binary analysis for ablation.

Claude acts as a first-class RE participant in a ReAct tool-calling loop.
Prior findings from func_id_db prime each analysis via RAG retrieval.
Results are persisted back as ANGR_INFERRED records for future analyses.

Quick start:
    from llm_analyst import AgentLoop, ToolRegistry
    from func_id_db import FuncDB

    db  = FuncDB.open('~/.ablation/func_id.db')
    reg = ToolRegistry('/path/to/lina', func_db=db)
    loop = AgentLoop(reg, func_db=db, product='lina', version='9.16.4.18')
    result = loop.run(0x212a669, task='name_function')
    print(result.name, result.confidence)
"""

from .agent_loop    import AgentLoop, AnalysisResult
from .tool_registry import ToolRegistry, TOOL_SCHEMAS
from .context_builder import ContextBuilder
from .rag_retriever import RAGRetriever

__all__ = [
    'AgentLoop',
    'AnalysisResult',
    'ToolRegistry',
    'TOOL_SCHEMAS',
    'ContextBuilder',
    'RAGRetriever',
]
