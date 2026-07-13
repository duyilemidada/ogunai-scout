# engine/ogunai/llm_adapter.py
"""
Model-Agnostic LLM Interface with Native Tool Calling.

Three adapters: OpenAI-compatible (covers Groq, vLLM, LM Studio),
Ollama (local), and Anthropic Claude.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import json

from .config import ENGINE_CONFIG, get_llm_config


class BaseLLMAdapter(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def invoke(self, messages: List[Dict[str, str]], temperature: float = 0.4) -> str:
        pass

    def invoke_with_tools(self, messages: List[Dict[str, str]], tools: List[Dict[str, Any]], temperature: float = 0.4) -> Dict[str, Any]:
        """
        Native tool calling. Returns a dict: {"text": "...", "tool_calls": [{"name": "...", "arguments": {...}}]}
        If an adapter doesn't support this, it falls back to text and empty tool calls.
        """
        text = self.invoke(messages, temperature)
        return {"text": text, "tool_calls": []}

    def get_model_info(self) -> Dict[str, Any]:
        return {"provider": self.__class__.__name__, "model": self.config.get("model", "unknown")}


class OpenAICompatibleAdapter(BaseLLMAdapter):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=config["base_url"],
                api_key=config.get("api_key") or "not-needed"
            )
        except ImportError:
            raise ImportError("Run: pip install openai")

    def invoke(self, messages: List[Dict[str, str]], temperature: float = 0.4) -> str:
        response = self._client.chat.completions.create(
            model=self.config["model"], messages=messages,
            temperature=temperature, max_tokens=ENGINE_CONFIG["max_tokens"]
        )
        return response.choices[0].message.content

    def invoke_with_tools(self, messages: List[Dict[str, str]], tools: List[Dict[str, Any]], temperature: float = 0.4) -> Dict[str, Any]:
        try:
            response = self._client.chat.completions.create(
                model=self.config["model"], messages=messages,
                temperature=temperature, max_tokens=ENGINE_CONFIG["max_tokens"],
                tools=tools, tool_choice="auto"
            )
            msg = response.choices[0].message
            tool_calls = []
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        args = {}
                    tool_calls.append({"name": tc.function.name, "arguments": args})
            return {"text": msg.content or "", "tool_calls": tool_calls}
        except Exception as e:
            print(f"[OPENAI ADAPTER] Tool calling failed, falling back to text: {e}")
            return super().invoke_with_tools(messages, tools, temperature)


class OllamaAdapter(BaseLLMAdapter):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            import ollama
            self._client = ollama
        except ImportError:
            raise ImportError("Run: pip install ollama")

    def invoke(self, messages: List[Dict[str, str]], temperature: float = 0.4) -> str:
        response = self._client.chat(
            model=self.config["model"], messages=messages,
            options={"temperature": temperature, "num_predict": ENGINE_CONFIG["max_tokens"]}
        )
        return response["message"]["content"]

    def invoke_with_tools(self, messages: List[Dict[str, str]], tools: List[Dict[str, Any]], temperature: float = 0.4) -> Dict[str, Any]:
        try:
            response = self._client.chat(
                model=self.config["model"], messages=messages,
                tools=tools,
                options={"temperature": temperature, "num_predict": ENGINE_CONFIG["max_tokens"]}
            )
            msg = response.get("message", {})
            tool_calls = []
            if "tool_calls" in msg:
                for tc in msg["tool_calls"]:
                    func = tc.get("function", {})
                    tool_calls.append({
                        "name": func.get("name"),
                        "arguments": func.get("arguments", {})
                    })
            return {"text": msg.get("content", ""), "tool_calls": tool_calls}
        except Exception as e:
            print(f"[OLLAMA ADAPTER] Tool calling failed, falling back to text: {e}")
            return super().invoke_with_tools(messages, tools, temperature)


class AnthropicAdapter(BaseLLMAdapter):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=config["api_key"])
        except ImportError:
            raise ImportError("Run: pip install anthropic")

    def invoke(self, messages: List[Dict[str, str]], temperature: float = 0.4) -> str:
        system_parts = []
        conversation = []
        for msg in messages:
            if msg["role"] == "system": system_parts.append(msg["content"])
            else: conversation.append({"role": msg["role"], "content": msg["content"]})

        kwargs = {"model": self.config["model"], "messages": conversation, "max_tokens": ENGINE_CONFIG["max_tokens"], "temperature": temperature}
        if system_parts: kwargs["system"] = "\n\n".join(system_parts)

        response = self._client.messages.create(**kwargs)
        return response.content[0].text

    def invoke_with_tools(self, messages: List[Dict[str, str]], tools: List[Dict[str, Any]], temperature: float = 0.4) -> Dict[str, Any]:
        system_parts = []
        conversation = []
        for msg in messages:
            if msg["role"] == "system": system_parts.append(msg["content"])
            else: conversation.append({"role": msg["role"], "content": msg["content"]})

        anthropic_tools = [{"name": t["function"]["name"], "description": t["function"]["description"], "input_schema": t["function"]["parameters"]} for t in tools]
        
        kwargs = {"model": self.config["model"], "messages": conversation, "max_tokens": ENGINE_CONFIG["max_tokens"], "temperature": temperature, "tools": anthropic_tools}
        if system_parts: kwargs["system"] = "\n\n".join(system_parts)

        response = self._client.messages.create(**kwargs)
        text = ""
        tool_calls = []
        for block in response.content:
            if block.type == "text": text += block.text
            elif block.type == "tool_use": tool_calls.append({"name": block.name, "arguments": block.input})
            
        return {"text": text, "tool_calls": tool_calls}


_REGISTRY = {
    "openai_compatible": OpenAICompatibleAdapter,
    "ollama": OllamaAdapter,
    "anthropic": AnthropicAdapter,
}

def get_default_adapter() -> BaseLLMAdapter:
    provider = ENGINE_CONFIG["llm_provider"]
    if provider not in _REGISTRY:
        raise ValueError(f"Unknown provider: {provider}. Available: {list(_REGISTRY)}")
    return _REGISTRY[provider](get_llm_config())