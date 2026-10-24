from __future__ import annotations

import gzip
import ipaddress
import json
import re
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from .config import Settings

MAX_SCAN_BYTES = 1_000_000
PREVIEW_CHARS = 6000


@dataclass(frozen=True)
class Provider:
    name: str
    hosts: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    local: bool = False


PROVIDERS: tuple[Provider, ...] = (
    Provider("OpenAI", ("api.openai.com", "chatgpt.com")),
    Provider("Anthropic", ("api.anthropic.com", "claude.ai")),
    Provider("Google Gemini", ("generativelanguage.googleapis.com", "aiplatform.googleapis.com")),
    Provider("OpenRouter", ("openrouter.ai",)),
    Provider("Mistral AI", ("api.mistral.ai",)),
    Provider("Cohere", ("api.cohere.ai", "api.cohere.com")),
    Provider("Groq", ("api.groq.com",)),
    Provider("xAI", ("api.x.ai",)),
    Provider("DeepSeek", ("api.deepseek.com",)),
    Provider("阿里云百炼 / DashScope", ("dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com")),
    Provider("Moonshot / Kimi", ("api.moonshot.cn", "api.moonshot.ai")),
    Provider("智谱 BigModel", ("open.bigmodel.cn",)),
    Provider("百度千帆", ("qianfan.baidubce.com", "aip.baidubce.com")),
    Provider("火山方舟", ("ark.cn-beijing.volces.com", "ark.cn-shanghai.volces.com")),
    Provider("Hugging Face", ("api-inference.huggingface.co", "router.huggingface.co", "huggingface.co")),
    Provider("Together AI", ("api.together.xyz",)),
    Provider("Fireworks AI", ("api.fireworks.ai",)),
    Provider("Perplexity", ("api.perplexity.ai",)),
    Provider("SiliconFlow", ("api.siliconflow.cn",)),
    Provider("302.AI", ("api.302.ai",)),
    Provider("Novita AI", ("api.novita.ai",)),
    Provider("Replicate", ("api.replicate.com",)),
    Provider("Stability AI", ("api.stability.ai",)),
    Provider("ElevenLabs", ("api.elevenlabs.io",)),
    Provider("AssemblyAI", ("api.assemblyai.com",)),
    Provider("Voyage AI", ("api.voyageai.com",)),
    Provider("Jina AI", ("api.jina.ai", "jina.ai")),
    Provider("LangSmith", ("api.smith.langchain.com", "api.langsmith.com")),
    Provider("Ollama（本地）", ("localhost", "127.0.0.1", "::1"), (11434,), local=True),
    Provider("LM Studio（本地）", ("localhost", "127.0.0.1", "::1"), (1234,), local=True),
    Provider("LocalAI（本地）", ("localhost", "127.0.0.1", "::1"), (8080,), local=True),
)

AI_PATH_PATTERNS = (
    re.compile(r"/v1/chat/completions$", re.I),
    re.compile(r"/chat/completions$", re.I),
    re.compile(r"/v1/messages$", re.I),
    re.compile(r"/v1/responses$", re.I),
    re.compile(r"/v1/completions$", re.I),
    re.compile(r"/v1/embeddings$", re.I),
    re.compile(r"/v1/rerank$|/rerank$", re.I),
    re.compile(r"/v1/images?/", re.I),
    re.compile(r"/v1/audio/", re.I),
    re.compile(r"/v1/files$", re.I),
    re.compile(r"/v1/batches$", re.I),
    re.compile(r"/v1/fine_tuning/", re.I),
    re.compile(r"/v1/models$", re.I),
    re.compile(r"/api/(chat|generate|embed|embeddings|tags|show)$", re.I),
    re.compile(r"/api/v1/(chat|generate|completions?)$", re.I),
    re.compile(r":(generateContent|streamGenerateContent)$", re.I),
    re.compile(r"/v1beta/models/", re.I),
    re.compile(r"/(invoke|converse|predict)$", re.I),
    re.compile(r"/openai/", re.I),
    re.compile(r"/v1/(responses|assistants|threads|runs)", re.I),
)

AI_JSON_KEYS = {
    "model",
    "messages",
    "prompt",
    "input",
    "contents",
    "system",
    "tools",
    "tool_choice",
    "max_tokens",
    "max_output_tokens",
    "temperature",
    "top_p",
    "stream",
    "response_format",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "system_instruction",
}
AI_SDK_HEADER_HINTS = (
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "llama-index",
    "ollama",
    "google-generativeai",
    "genai",
    "cohere",
    "mistral",
)

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "openai-api-key",
    "anthropic-api-key",
    "x-auth-token",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    score: int
    direction: str = "request"
    detail: str = ""
    evidence: str = ""
    scored: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "score": self.score if self.scored else 0,
            "direction": self.direction,
            "detail": self.detail,
            "evidence": self.evidence,
            "action": "observe",
        }


@dataclass
class Assessment:
    provider: str = ""
    category: str = "other"
    endpoint_kind: str = "other"
    model: str = ""
    risk: int = 0
    severity: str = "info"
    action: str = "observe"
    findings: list[Finding] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    req_preview: str = ""
    path: str = ""
    request_bytes: int = 0
    headers_preview: dict[str, str] = field(default_factory=dict)
    stream: bool = False
    note: str = ""

    def is_ai(self) -> bool:
        return self.category.startswith("ai_")


@dataclass(frozen=True)
class TextRule:
    rule_id: str
    title: str
    category: str
    score: int
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    strong: bool = False


def _valid_cn_id(value: str) -> bool:
    if len(value) != 18:
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checks = "10X98765432"
    try:
        total = sum(int(value[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    return checks[total % 11] == value[17].upper()


def _valid_luhn(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


TEXT_RULES: tuple[TextRule, ...] = (
    TextRule(
        "secret.openai_key",
        "检测到 OpenAI API Key",
        "secret",
        55,
        re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
        strong=True,
    ),
    TextRule("secret.anthropic_key", "检测到 Anthropic API Key", "secret", 55, re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), strong=True),
    TextRule("secret.aws_access_key", "检测到 AWS Access Key", "secret", 50, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), strong=True),
    TextRule("secret.github_token", "检测到 GitHub Token", "secret", 50, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), strong=True),
    TextRule("secret.google_api_key", "检测到 Google API Key", "secret", 45, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), strong=True),
    TextRule("secret.slack_token", "检测到 Slack Token", "secret", 45, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), strong=True),
    TextRule(
        "secret.private_key",
        "检测到私钥内容",
        "secret",
        60,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        strong=True,
    ),
    TextRule(
        "secret.jwt",
        "检测到 JWT 令牌",
        "secret",
        28,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        strong=True,
    ),
    TextRule("pii.cn_id", "检测到中国居民身份证号", "pii", 40, re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"), _valid_cn_id),
    TextRule("pii.bank_card", "检测到银行卡号", "pii", 45, re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), _valid_luhn),
    TextRule("pii.phone", "检测到中国手机号", "pii", 16, re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    TextRule("pii.email", "检测到邮箱地址", "pii", 6, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

GENERIC_ASSIGNMENT = re.compile(
    r"""(?i)((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|credential|authorization)\s*[:=]\s*["']?)([^\s"',;}{]{8,})"""
)
DOTENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")
CODE_FENCE = re.compile(r"```[\s\S]{20,}?```")
DIFF_BLOCK = re.compile(r"(?m)^(?:diff --git |--- a/|\+\+\+ b/)")
FILE_REFERENCE = re.compile(
    r"(?i)(?:[A-Z]:\\[^\s\"'<>|]{3,}|/(?:Users|home|root|etc|var)/[^\s\"'<>]{3,}|[\w.-]+\.(?:py|js|ts|tsx|jsx|java|go|rs|rb|php|cs|cpp|c|h|sql|env|pem|key|kdbx|docx|xlsx|pdf|csv))"
)
MULTIPART_FILENAME = re.compile(rb'filename="([^"\r\n]{1,200})"', re.I)


def severity_for_risk(risk: int) -> str:
    if risk >= 85:
        return "critical"
    if risk >= 70:
        return "high"
    if risk >= 45:
        return "medium"
    if risk >= 25:
        return "low"
    return "info"


def severity_for_rule(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def _content_type(headers: dict[str, str]) -> tuple[str, str]:
    raw = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            raw = value
            break
    mime = raw.split(";", 1)[0].strip().lower()
    charset = "utf-8"
    match = re.search(r"charset=([\w-]+)", raw, re.I)
    if match:
        charset = match.group(1)
    return mime, charset


def _decode_body(body: bytes, content_type: str, headers: dict[str, str]) -> str:
    if not body:
        return ""
    encoding = ""
    for key, value in headers.items():
        if key.lower() == "content-encoding":
            encoding = value.lower().strip()
            break
    try:
        if encoding == "gzip":
            body = gzip.decompress(body)
        elif encoding == "deflate":
            body = zlib.decompress(body)
    except (OSError, zlib.error):
        pass
    _, charset = _content_type(headers)
    try:
        return body.decode(charset, "replace")
    except (LookupError, UnicodeDecodeError):
        return body.decode("utf-8", "replace")


def _is_private_host(host: str) -> bool:
    if host in ("localhost", "host.docker.internal") or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback
    except ValueError:
        return False


def _match_provider(host: str, port: int) -> Provider | None:
    for provider in PROVIDERS:
        for candidate in provider.hosts:
            if host == candidate or host.endswith("." + candidate):
                if provider.ports and port not in provider.ports:
                    continue
                return provider
    return None


def _endpoint_kind(path: str) -> str:
    low = path.lower()
    if re.search(r"chat|messages|responses|completions|generate|converse|invoke", low):
        return "chat"
    if "embed" in low or "rerank" in low:
        return "embeddings"
    if re.search(r"files?|upload|attachments?|batches", low):
        return "files"
    if re.search(r"images?|audio|speech|transcri", low):
        return "media"
    if re.search(r"models?|tags", low):
        return "models"
    if re.search(r"fine_tuning|threads|runs|assistants", low):
        return "platform"
    return "other"


def _mask_cn_id(value: str) -> str:
    return value[:3] + "*" * 11 + value[-4:]


def _mask_phone(value: str) -> str:
    return value[:3] + "****" + value[-4:]


def _mask_email(value: str) -> str:
    name, _, domain = value.partition("@")
    return (name[:1] or "*") + "***@" + domain


def _mask_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return "**** **** **** " + digits[-4:]


def _mask_secret(value: str) -> str:
    clean = value.strip().strip("'\"")
    if len(clean) <= 10:
        return "«REDACTED»"
    return clean[:4] + "…" + clean[-2:] + f" (len={len(clean)})"


def redact_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(
        r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----",
        "«REDACTED:PRIVATE_KEY»",
        text,
    )
    text = re.sub(r"\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}", lambda m: _mask_secret(m.group(0)), text)
    text = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "«REDACTED:AWS_KEY»", text)
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "«REDACTED:GITHUB_TOKEN»", text)
    text = re.sub(r"\bAIza[0-9A-Za-z_-]{30,}\b", "«REDACTED:GOOGLE_KEY»", text)
    text = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]{15,}\b", "«REDACTED:SLACK_TOKEN»", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "«REDACTED:JWT»", text)
    text = GENERIC_ASSIGNMENT.sub(lambda m: m.group(1) + "«REDACTED»", text)
    for match in list(re.finditer(TEXT_RULES[8].pattern, text)):
        if _valid_cn_id(match.group(0)):
            text = text.replace(match.group(0), _mask_cn_id(match.group(0)))
    for match in list(re.finditer(TEXT_RULES[9].pattern, text)):
        if _valid_luhn(match.group(0)):
            text = text.replace(match.group(0), _mask_card(match.group(0)))
    for match in list(re.finditer(TEXT_RULES[10].pattern, text)):
        text = text.replace(match.group(0), _mask_phone(match.group(0)))
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", lambda m: _mask_email(m.group(0)), text)
    return text


def sanitize_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    keep = {
        "content-type",
        "content-length",
        "user-agent",
        "accept",
        "content-encoding",
        "x-stainless-lang",
        "x-stainless-package-version",
        "openai-organization",
        "openai-project",
        "anthropic-version",
        "x-goog-api-client",
        "x-request-id",
        "traceparent",
    }
    result: dict[str, str] = {}
    auth_seen = False
    for key, value in headers:
        low = key.lower()
        if low in SENSITIVE_HEADERS:
            auth_seen = True
            continue
        if low in keep and len(result) < 16:
            result[low] = value[:240]
    if auth_seen:
        result["authorization"] = "«present, value hidden»"
    return result


def _json_dict(text: str) -> dict[str, Any] | None:
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        data = next((item for item in data if isinstance(item, dict)), None)
    return data if isinstance(data, dict) else None


def _ai_signals(path: str, headers: dict[str, str], data: dict[str, Any] | None, mime: str) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if any(pattern.search(path) for pattern in AI_PATH_PATTERNS):
        reasons.append("AI API 路径")
    if data:
        keys = {str(k).lower() for k in data}
        hits = sorted(keys & AI_JSON_KEYS)
        if "model" in keys and keys & {"messages", "prompt", "input", "contents", "system_instruction"}:
            reasons.append("模型请求字段")
        elif len(hits) >= 3:
            reasons.append("LLM 参数特征")
        elif "messages" in keys and isinstance(data.get("messages"), list):
            reasons.append("messages 会话结构")
    ua = ""
    for key, value in headers.items():
        if key.lower() == "user-agent":
            ua = value.lower()
            break
    if any(hint in ua for hint in AI_SDK_HEADER_HINTS):
        reasons.append("AI SDK User-Agent")
    header_names = {k.lower() for k in headers}
    if {"x-stainless-lang", "anthropic-version", "x-goog-api-client"} & header_names:
        reasons.append("AI SDK 请求头")
    if mime == "application/x-ndjson" and "openai" in ua:
        reasons.append("流式 AI 请求")
    return bool(reasons), reasons


def _extract_model(data: dict[str, Any] | None) -> str:
    if not data:
        return ""
    for key in ("model", "model_id", "modelId"):
        value = data.get(key)
        if isinstance(value, str) and 0 < len(value) <= 120:
            return value
    return ""


def _upload_filenames(body: bytes) -> list[str]:
    if not body:
        return []
    names = []
    for match in MULTIPART_FILENAME.finditer(body[:MAX_SCAN_BYTES]):
        try:
            name = match.group(1).decode("utf-8")
        except UnicodeDecodeError:
            name = match.group(1).decode("latin-1", "replace")
        if name and name not in names:
            names.append(name[:180])
    return names[:8]


def _finding_evidence(text: str, match: re.Match[str], mask: Callable[[str], str] | None = None) -> str:
    value = match.group(0)
    if mask:
        return mask(value)
    if len(value) > 80:
        return value[:40] + "…" + value[-8:]
    return redact_text(value)


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def inspect(
        self,
        method: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        body_truncated: bool = False,
        process_family: str = "",
        app_kind: str = "",
    ) -> Assessment:
        parsed = urlsplit(path)
        path_only = parsed.path or "/"
        query = parsed.query
        mime, _ = _content_type(headers)
        body = body or b""
        if len(body) > MAX_SCAN_BYTES:
            body = body[:MAX_SCAN_BYTES]
            body_truncated = True
        text = _decode_body(body, mime, headers)
        query_text = query[:20_000]
        scan_text = text
        if query_text and not body:
            scan_text = query_text
        data = _json_dict(text) if body else None

        provider = _match_provider(host.lower(), port)
        has_ai_path = any(pattern.search(path_only) for pattern in AI_PATH_PATTERNS)
        ai_signal, reasons = _ai_signals(path_only, headers, data, mime)
        if provider:
            category = "ai_local" if provider.local else "ai_service"
            provider_name = provider.name
        elif has_ai_path and _is_private_host(host):
            category = "ai_local"
            provider_name = "自托管模型端点"
        elif ai_signal:
            category = "ai_candidate"
            provider_name = "未识别 AI 端点"
        else:
            category = "other"
            provider_name = ""
        endpoint_kind = _endpoint_kind(path_only)
        model = _extract_model(data)
        tags: list[str] = []
        if category != "other":
            tags.append(category.replace("_", "-"))
        if endpoint_kind != "other":
            tags.append("endpoint-" + endpoint_kind)
        findings: list[Finding] = []
        strong_secret_found = False

        if category == "ai_candidate":
            findings.append(
                Finding(
                    "endpoint.unknown_ai",
                    "发往未识别的 AI 风格端点",
                    "endpoint",
                    "low",
                    0,
                    detail="主机不在已知 AI 服务清单中，但路径/JSON 结构符合 AI 请求特征：" + "、".join(reasons),
                    scored=False,
                )
            )
        if endpoint_kind in ("files", "media") and method.upper() in ("POST", "PUT", "PATCH"):
            findings.append(
                Finding(
                    "endpoint.file_upload",
                    "文件/媒体上传端点",
                    "file",
                    "low",
                    12,
                    detail="请求目标为文件或媒体上传接口",
                    evidence=path_only,
                )
            )
            if "file" not in tags:
                tags.append("file")
        if mime == "multipart/form-data":
            names = _upload_filenames(body)
            if names:
                findings.append(
                    Finding(
                        "file.multipart_upload",
                        "检测到文件上传",
                        "file",
                        "medium",
                        22,
                        detail=f"multipart 上传了 {len(names)} 个文件",
                        evidence=", ".join(names),
                    )
                )
                tags.append("file")
        if category != "other" and method.upper() in ("POST", "PUT", "PATCH") and len(body) > 64_000 and mime not in ("multipart/form-data",):
            score = 30 if len(body) > 1_000_000 else 18
            findings.append(
                Finding(
                    "volume.large_body",
                    "较大请求正文",
                    "volume",
                    "medium" if score >= 25 else "low",
                    score,
                    detail=f"请求正文约 {len(body):,} 字节",
                )
            )
            tags.append("volume")

        scan_spans: list[tuple[int, int]] = []
        if scan_text:
            for rule in TEXT_RULES:
                matches = []
                for match in rule.pattern.finditer(scan_text):
                    if rule.validator and not rule.validator(match.group(0)):
                        continue
                    if any(not (match.end() <= start or match.start() >= end) for start, end in scan_spans):
                        continue
                    matches.append(match)
                    scan_spans.append((match.start(), match.end()))
                    if len(matches) >= 8:
                        break
                if not matches:
                    continue
                if rule.category == "secret" and rule.strong:
                    strong_secret_found = True
                mask = None
                if rule.rule_id == "pii.cn_id":
                    mask = _mask_cn_id
                elif rule.rule_id == "pii.phone":
                    mask = _mask_phone
                elif rule.rule_id == "pii.email":
                    mask = _mask_email
                elif rule.rule_id == "pii.bank_card":
                    mask = _mask_card
                elif rule.category == "secret":
                    mask = _mask_secret
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.title,
                        rule.category,
                        severity_for_rule(rule.score),
                        rule.score,
                        detail=f"命中 {len(matches)} 处" + ("（正文已截断扫描）" if body_truncated else ""),
                        evidence=_finding_evidence(scan_text, matches[0], mask),
                    )
                )
                if rule.category not in tags:
                    tags.append(rule.category)

            if not strong_secret_found:
                generic = [m for m in GENERIC_ASSIGNMENT.finditer(scan_text) if not _looks_placeholder(m.group(2))][:5]
                if generic:
                    findings.append(
                        Finding(
                            "secret.generic_assignment",
                            "疑似凭据/密钥赋值",
                            "secret",
                            "medium",
                            35,
                            detail=f"命中 {len(generic)} 处键值型凭据",
                            evidence=redact_text(generic[0].group(0))[:120],
                        )
                    )
                    if "secret" not in tags:
                        tags.append("secret")

            dotenv_lines = DOTENV_LINE.findall(scan_text)
            if len(dotenv_lines) >= 3:
                findings.append(
                    Finding(
                        "data.dotenv",
                        "疑似 .env / 环境变量内容",
                        "secret",
                        "medium",
                        45,
                        detail=f"检测到 {len(dotenv_lines)} 行环境变量赋值",
                        evidence=", ".join(line.split("=", 1)[0][:40] for line in dotenv_lines[:5]),
                    )
                )
                if "secret" not in tags:
                    tags.append("secret")

            if CODE_FENCE.search(scan_text):
                findings.append(
                    Finding("code.fence", "包含代码块", "code", "low", 14, detail="请求正文包含 Markdown 代码块")
                )
                tags.append("code")
            elif DIFF_BLOCK.search(scan_text):
                findings.append(
                    Finding("code.diff", "包含代码 Diff", "code", "low", 16, detail="请求正文包含代码补丁/diff")
                )
                tags.append("code")
            file_refs = FILE_REFERENCE.findall(scan_text[:200_000])
            if file_refs:
                findings.append(
                    Finding(
                        "data.file_reference",
                        "包含文件路径或源码文件名",
                        "code",
                        "low",
                        12,
                        detail=f"检测到 {len(file_refs)} 处文件引用",
                        evidence=redact_text(", ".join(str(x) for x in file_refs[:4]))[:180],
                    )
                )
                if "code" not in tags:
                    tags.append("code")

        if body and mime in ("application/octet-stream", "application/zip", "application/x-zip-compressed") and category == "other":
            if len(body) > 64_000:
                findings.append(
                    Finding(
                        "egress.binary_upload",
                        "向非 AI 目标上传二进制数据",
                        "file",
                        "medium",
                        25,
                        detail=f"未知目标收到约 {len(body):,} 字节二进制正文",
                    )
                )
                tags.append("file")

        if category == "other":
            sensitive = any(f.category in ("secret", "pii", "code", "file", "volume") for f in findings)
            if sensitive:
                findings.append(
                    Finding(
                        "egress.unknown_destination",
                        "敏感数据发往未识别目标",
                        "endpoint",
                        "medium",
                        15,
                        detail="请求包含敏感内容，但目标既不是已知 AI 服务，也不符合 AI 端点特征",
                    )
                )

        request_score = sum(f.score for f in findings if f.scored and f.direction == "request")
        base = {"ai_service": 16, "ai_local": 8, "ai_candidate": 34, "other": 4}[category]
        if category == "other" and not findings:
            base = 2
        if method.upper() in ("GET", "HEAD") and not body and not findings:
            base = min(base, 6 if category != "other" else 1)
        risk = min(100, base + request_score)
        severity = severity_for_risk(risk)
        if self.settings.blocking_enabled and risk >= self.settings.block_risk:
            action = "block"
        elif risk >= 45:
            action = "alert"
        else:
            action = "observe"
        if process_family == "system" and category == "other":
            tags.append("system-process")
        if app_kind:
            tags.append("app:" + app_kind)

        preview = self._preview(text, mime)
        if query:
            preview = ("URL 查询串（已脱敏）:\n" + redact_text(query[:2000]) + "\n\n" + preview).strip()
        if not preview and body:
            preview = f"[{mime or 'binary'}] {len(body):,} bytes（未解码）"
        return Assessment(
            provider=provider_name,
            category=category,
            endpoint_kind=endpoint_kind,
            model=model,
            risk=risk,
            severity=severity,
            action=action,
            findings=findings,
            tags=sorted(set(tags)),
            req_preview=preview[:PREVIEW_CHARS],
            path=path_only,
            request_bytes=len(body),
            headers_preview=sanitize_headers(headers.items()),
            stream=bool(data.get("stream")) if data else False,
            note="正文超出扫描上限，仅分析前 1MB" if body_truncated else "",
        )

    def inspect_response(
        self, headers: dict[str, str], body: bytes | None, status: int, path: str
    ) -> tuple[str, list[Finding]]:
        body = body or b""
        mime, _ = _content_type(headers)
        if len(body) > MAX_SCAN_BYTES:
            body = body[:MAX_SCAN_BYTES]
        text = _decode_body(body, mime, headers) if body else ""
        findings: list[Finding] = []
        if text:
            seen = set()
            for rule in TEXT_RULES:
                if rule.category not in ("secret", "pii"):
                    continue
                for match in rule.pattern.finditer(text):
                    if rule.validator and not rule.validator(match.group(0)):
                        continue
                    mask = _mask_secret if rule.category == "secret" else None
                    findings.append(
                        Finding(
                            rule.rule_id + ".response",
                            rule.title + "（响应）",
                            rule.category,
                            severity_for_rule(rule.score),
                            0,
                            direction="response",
                            detail="响应内容中命中敏感信息；不计入请求外发风险",
                            evidence=_finding_evidence(text, match, mask),
                            scored=False,
                        )
                    )
                    seen.add(rule.rule_id)
                    break
                if len(findings) >= 6:
                    break
        preview = self._preview(text, mime) if text else ""
        if not preview and body:
            preview = f"[{mime or 'binary'} 响应] {len(body):,} bytes"
        return preview[:PREVIEW_CHARS], findings

    @staticmethod
    def _preview(text: str, mime: str) -> str:
        if not text:
            return ""
        candidate = text
        if mime in ("application/json", "application/x-ndjson") or mime.endswith("+json"):
            if len(text) <= 200_000:
                try:
                    data = json.loads(text)
                    candidate = json.dumps(data, ensure_ascii=False, indent=2)
                except (ValueError, TypeError):
                    candidate = text
        candidate = redact_text(candidate)
        candidate = re.sub(r"[ \t]+\n", "\n", candidate)
        candidate = re.sub(r"\n{3,}", "\n\n", candidate)
        return candidate[:PREVIEW_CHARS]


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    if len(value) < 8:
        return True
    if any(token in low for token in ("example", "your_", "your-", "changeme", "placeholder", "redacted", "xxxx", "****")):
        return True
    if len(set(value)) <= 2:
        return True
    return False
