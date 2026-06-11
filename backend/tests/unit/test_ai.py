from types import SimpleNamespace

import pytest

from scanr.ai.assist.summary import build_messages, summarize_findings
from scanr.ai.llm.anthropic import AnthropicProvider
from scanr.ai.llm.base import Completion, LLMProvider, Usage
from scanr.ai.llm.openai_compat import OpenAICompatProvider
from scanr.ai.llm import factory


class FakeProvider(LLMProvider):
    def __init__(self, reply: str = "SUMMARY TEXT"):
        self.name = "fake"
        self.model = "fake-1"
        self.reply = reply
        self.calls: list = []

    async def complete(self, *, system, messages, tools=None, max_tokens=2048):
        self.calls.append({"system": system, "messages": messages, "tools": tools, "max_tokens": max_tokens})
        return Completion(text=self.reply, usage=Usage(input_tokens=10, output_tokens=5))


def test_usage_add():
    total = Usage(1, 2, 3) + Usage(10, 20, 30)
    assert (total.input_tokens, total.output_tokens, total.cached_input_tokens) == (11, 22, 33)


def test_build_messages_orders_and_fences():
    findings = [
        {"severity": "low", "title": "Low thing", "host_ip": "192.0.2.1"},
        {"severity": "critical", "title": "Critical thing", "host_ip": "192.0.2.2", "port_number": 443},
    ]
    msgs = build_messages(findings)
    assert len(msgs) == 1
    body = msgs[0].content
    # Critical must be listed before low (severity-sorted)
    assert body.index("Critical thing") < body.index("Low thing")
    # Untrusted data is fenced
    assert "<findings>" in body and "</findings>" in body
    assert "192.0.2.2:443" in body


def test_build_messages_truncates_long_description():
    findings = [{"severity": "high", "title": "X", "host_ip": "192.0.2.1", "description": "A" * 1000}]
    body = build_messages(findings)[0].content
    assert "…" in body
    assert "A" * 1000 not in body


@pytest.mark.asyncio
async def test_summarize_empty_findings_skips_provider():
    provider = FakeProvider()
    result = await summarize_findings(provider, [])
    assert result.finding_count == 0
    assert "clean" in result.text.lower()
    assert provider.calls == []  # no API call for an empty scan


@pytest.mark.asyncio
async def test_summarize_calls_provider_and_returns_text():
    provider = FakeProvider(reply="## Executive summary\nAll good.")
    findings = [{"severity": "high", "title": "Open Redis", "host_ip": "192.0.2.5", "port_number": 6379}]
    result = await summarize_findings(provider, findings, max_tokens=512)
    assert result.text.startswith("## Executive summary")
    assert result.finding_count == 1
    assert result.provider == "fake" and result.model == "fake-1"
    assert result.usage.output_tokens == 5
    # The model received the fenced findings and the system instructions
    call = provider.calls[0]
    assert call["max_tokens"] == 512
    assert "untrusted data" in call["system"].lower()
    assert any("Open Redis" in m.content for m in call["messages"])


@pytest.mark.asyncio
async def test_report_empty_skips_provider():
    from scanr.ai.assist.report import generate_report_narrative
    provider = FakeProvider()
    result = await generate_report_narrative(provider, [])
    assert result.finding_count == 0
    assert provider.calls == []
    assert "Executive Summary" in result.text


@pytest.mark.asyncio
async def test_report_calls_provider():
    from scanr.ai.assist.report import generate_report_narrative
    provider = FakeProvider(reply="## Executive Summary\nstuff")
    findings = [{"severity": "critical", "title": "RCE", "host_ip": "192.0.2.9"}]
    result = await generate_report_narrative(provider, findings, scan_name="Engagement X")
    assert result.text.startswith("## Executive Summary")
    call = provider.calls[0]
    assert "Engagement X" in call["messages"][0].content
    assert "untrusted data" in call["system"].lower()


def test_fp_parse_items_tolerant():
    from scanr.ai.assist.false_positive import _parse_items
    valid = {"a", "b"}
    # fenced + prose around the array, an invented id, a bad confidence
    text = (
        "Here you go:\n```json\n"
        '[{"id":"a","confidence":"high","reason":"weak match"},'
        '{"id":"zzz","confidence":"high","reason":"invented"},'
        '{"id":"b","confidence":"bogus","reason":"x"}]\n```'
    )
    items = _parse_items(text, valid)
    ids = {i["id"] for i in items}
    assert ids == {"a", "b"}  # invented id dropped
    b = next(i for i in items if i["id"] == "b")
    assert b["confidence"] == "low"  # invalid confidence normalized


def test_fp_parse_items_garbage():
    from scanr.ai.assist.false_positive import _parse_items
    assert _parse_items("no json here", {"a"}) == []


@pytest.mark.asyncio
async def test_false_positives_flags_and_filters():
    from scanr.ai.assist.false_positive import test_false_positives
    provider = FakeProvider(reply='[{"id":"f1","confidence":"high","reason":"generic banner match"}]')
    findings = [
        {"id": "f1", "severity": "medium", "title": "Maybe", "host_ip": "192.0.2.1", "evidence": "weak"},
        {"id": "f2", "severity": "low", "title": "Already FP", "host_ip": "192.0.2.1", "false_positive": True},
    ]
    result = await test_false_positives(provider, findings)
    assert result.assessed_count == 1  # f2 skipped (already FP)
    assert [i["id"] for i in result.items] == ["f1"]
    # already-FP findings are not even sent to the model
    assert "Already FP" not in provider.calls[0]["messages"][0].content


@pytest.mark.asyncio
async def test_false_positives_all_already_fp_skips_provider():
    from scanr.ai.assist.false_positive import test_false_positives
    provider = FakeProvider()
    findings = [{"id": "f1", "severity": "low", "title": "x", "false_positive": True}]
    result = await test_false_positives(provider, findings)
    assert result.items == [] and result.assessed_count == 0
    assert provider.calls == []


def _settings(**overrides):
    base = dict(
        ai_provider="anthropic",
        ai_model="",
        anthropic_api_key="",
        openai_api_key="",
        deepseek_api_key="",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_factory_unknown_provider(monkeypatch):
    monkeypatch.setattr(factory, "get_settings", lambda: _settings())
    with pytest.raises(factory.AIProviderError):
        factory.build_provider("not-a-provider")


def test_factory_missing_key(monkeypatch):
    monkeypatch.setattr(factory, "get_settings", lambda: _settings(anthropic_api_key=""))
    with pytest.raises(factory.AIProviderError):
        factory.build_provider("anthropic")


def test_factory_builds_anthropic(monkeypatch):
    monkeypatch.setattr(factory, "get_settings", lambda: _settings(anthropic_api_key="sk-test"))
    provider = factory.build_provider("anthropic")
    assert isinstance(provider, AnthropicProvider)
    assert provider.model == "claude-opus-4-8"  # provider default


def test_factory_builds_deepseek_with_base_url(monkeypatch):
    monkeypatch.setattr(factory, "get_settings", lambda: _settings(deepseek_api_key="sk-ds"))
    provider = factory.build_provider("deepseek", model="deepseek-chat")
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "deepseek"
    assert provider._base_url == "https://api.deepseek.com"


def test_factory_builds_openai(monkeypatch):
    monkeypatch.setattr(factory, "get_settings", lambda: _settings(openai_api_key="sk-oa"))
    provider = factory.build_provider("openai")
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.name == "openai" and provider._base_url is None
