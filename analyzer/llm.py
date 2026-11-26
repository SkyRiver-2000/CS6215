"""Thin OpenAI-compatible client wrapper with usage accounting."""

import json
import os
import re
import threading
import time
import types

from openai import OpenAI

DEFAULT_MODEL = "qwen/qwen3.8-27b"


class LLM:
    # all LLM calls go through OpenRouter (OpenAI-compatible API)
    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self, model=DEFAULT_MODEL, temperature=0.0, max_tokens=4096, timeout=180):
        # a short per-request timeout (plus retries) keeps a dropped connection from stalling a run
        self.timeout = timeout
        self.provider = "openrouter"
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise SystemExit("OPENROUTER_API_KEY is not set (see README, 'LLM access')")
        self.client = OpenAI(base_url=self.BASE_URL, api_key=key, timeout=timeout, max_retries=3)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.lock = threading.Lock()
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "seconds": 0.0}

    def chat(self, messages, tools=None, stream=False):
        """stream=True (no tools): stream the completion and return a response-like object. Used
        for long single calls (v0), where a non-streamed request may time out before it
        finishes.
        """
        start = time.monotonic()
        kwargs = dict(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        if tools:
            kwargs["tools"] = tools
        if stream and not tools:
            r = self._stream(kwargs)
        else:
            r = self.client.chat.completions.create(**kwargs)
        with self.lock:
            self.usage["calls"] += 1
            self.usage["seconds"] += time.monotonic() - start
            if r.usage:
                self.usage["prompt_tokens"] += r.usage.prompt_tokens
                self.usage["completion_tokens"] += r.usage.completion_tokens
        return r

    def _stream(self, kwargs):
        parts, finish, usage, model = [], None, None, self.model
        for ch in self.client.chat.completions.create(
            stream=True, stream_options={"include_usage": True}, **kwargs
        ):
            model = getattr(ch, "model", None) or model
            if getattr(ch, "usage", None):
                usage = ch.usage
            for c in ch.choices or []:
                if c.delta and c.delta.content:
                    parts.append(c.delta.content)
                if c.finish_reason:
                    finish = c.finish_reason
        msg = _ns(content="".join(parts), tool_calls=None)
        return _ns(choices=[_ns(message=msg, finish_reason=finish)], usage=usage, model=model)


def _ns(**kw):
    return types.SimpleNamespace(**kw)


def parse_json(text):
    """Extract the last JSON object from a model reply (tolerates think blocks / fences)."""
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"```(?:json)?", "", text)
    starts = [m.start() for m in re.finditer(r"\{", text)]
    for s in starts:
        depth = 0
        for e in range(s, len(text)):
            if text[e] == "{":
                depth += 1
            elif text[e] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[s : e + 1])
                    except json.JSONDecodeError:
                        break
    return None
