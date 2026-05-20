"""Native framework adapters for real external-agent L2 targets."""

from malleus.agent_frameworks.generic import GenericCallableAgentAdapter, load_generic_agent_adapter, serve_generic_agent_adapter
from malleus.agent_frameworks.langgraph import LangGraphAdapter, load_langgraph_adapter, serve_langgraph_adapter
from malleus.agent_frameworks.openai_agents import OpenAIAgentsAdapter, load_openai_agents_adapter, serve_openai_agents_adapter
from malleus.agent_frameworks.rag import LangChainRagAdapter, LlamaIndexRagAdapter, load_langchain_rag_adapter, load_llamaindex_rag_adapter, serve_langchain_rag_adapter, serve_llamaindex_rag_adapter
from malleus.agent_frameworks.tools import (
    MalleusGatewayTool,
    malleus_langchain_tools,
    malleus_langgraph_tools,
    malleus_openai_agent_tools,
    malleus_openai_function_schemas,
    malleus_tool,
    malleus_tools,
)

__all__ = [
    "GenericCallableAgentAdapter",
    "LangChainRagAdapter",
    "LangGraphAdapter",
    "LlamaIndexRagAdapter",
    "MalleusGatewayTool",
    "OpenAIAgentsAdapter",
    "load_generic_agent_adapter",
    "load_langchain_rag_adapter",
    "load_langgraph_adapter",
    "load_llamaindex_rag_adapter",
    "load_openai_agents_adapter",
    "malleus_langchain_tools",
    "malleus_langgraph_tools",
    "malleus_openai_agent_tools",
    "malleus_openai_function_schemas",
    "malleus_tool",
    "malleus_tools",
    "serve_generic_agent_adapter",
    "serve_langchain_rag_adapter",
    "serve_langgraph_adapter",
    "serve_llamaindex_rag_adapter",
    "serve_openai_agents_adapter",
]
