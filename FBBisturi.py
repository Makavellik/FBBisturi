from __future__ import annotations
import time, statistics, math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from time import sleep
from contextlib import contextmanager
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme
from rich.text import Text
from rich.columns import Columns
from rich.live import Live
from rich.progress import track
from datetime import datetime
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
from opentelemetry.sdk.trace.export import  ConsoleSpanExporter
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult


# =========================
# THEME
# =========================
theme = Theme({
    "neon": "bold magenta",
    "ok": "green",
    "warn": "yellow",
    "bad": "red",
    "dim": "dim",
    "title": "bold cyan",
})
console = Console(theme=theme)


class NeonConsoleSpanExporter(SpanExporter):
    """
    Exportador forense NEON CRYSTAL
    Visual, reactivo
    """

    def export(self, spans):
        for span in spans:
            duration_ms = (span.end_time - span.start_time) / 1_000_000


            # 🎨 COLOR DINÁMICO POR SEVERIDAD
            sev = span.attributes.get("signal.severity")
            border = (
                "bright_red" if sev == "critical" else
                "bright_yellow" if sev == "high" else
                "bright_magenta" if sev == "medium" else
                "bright_cyan"
            )

            title = Text(span.name, style="bold magenta")

            meta = [
                f"[cyan]Trace[/cyan]: {span.context.trace_id:#x}",
                f"[blue]Span[/blue]: {span.context.span_id:#x}",
                f"[green]Kind[/green]: {span.kind.name}",
                f"[yellow]Duración[/yellow]: {duration_ms:.1f} ms",
            ]

            if span.parent:
                meta.append(
                    f"[dim cyan]Parent[/dim cyan]: {span.parent.span_id:#x}"
                )

            attrs = []
            for k, v in span.attributes.items():
                attrs.append(
                    f"[bright_green]{k}[/bright_green] = [white]{v}[/white]"
                )

            body = Columns(
                [
                    "\n".join(meta),
                    "\n".join(attrs) if attrs else "[dim]sin atributos[/dim]",
                ],
                expand=True,
            )

            console.print(
                Panel(
                    body,
                    title=title,
                    border_style=border,
                    subtitle=f"[dim]{datetime.utcnow().isoformat()}Z[/dim]",
                )
            )

             # 🚨 ALERTA PULSANTE (SOLO VISUAL)
            if duration_ms > 800:
                neon_alert(
                    f"Span lento detectado: {span.name} ({duration_ms:.1f} ms)",
                    level="warn"
                )

            if duration_ms > 1500:
                neon_alert(
                    f"ANOMALÍA CRÍTICA DE LATENCIA: {span.name}",
                    level="critical"
                )

        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

# =========================
# TELEMETRY (FORENSIC-GRADE · 
# =========================

# ── Identidad forense del instrumento ─────────────────────────────
# Esta huella acompaña cada span como ADN operativo
resource = Resource.create({
    "service.name": "forensic-backend",
    "service.namespace": "trigger-forensics",
    "service.version": "1.0.0",

    # Modo de análisis
    "analysis.mode": "active",

    # Nivel de precisión (quirúrgico, no observacional)
    "telemetry.level": "surgical",
})

# ── Sampler inteligente ───────────────────────────────────────────
# Captura total ahora (100%) → reducible luego sin tocar el motor
sampler = TraceIdRatioBased(1.0)

# ── Proveedor de trazas (núcleo vital) ────────────────────────────
provider = TracerProvider(
    resource=resource,
    sampler=sampler,
)

# Registro global del proveedor
trace.set_tracer_provider(provider)

# ── Exportador base (Consola · Visión directa) ────────────────────
# Ideal para lectura humana, debugging forense y auditoría viva
provider.add_span_processor(
    SimpleSpanProcessor(
        NeonConsoleSpanExporter()
    )
)


# ── Tracer principal ──────────────────────────────────────────────
# Bisturí central: todo span nace desde aquí
tracer = trace.get_tracer("forensic-backend")

# =========================
# SAFETY
# =========================
class SafetyError(Exception):
    """Violación de contexto forense autorizado."""
    ...

def ensure_authorized(token: Optional[str]):
    """
    Verifica que la ejecución ocurre bajo un
    contexto explícitamente autorizado.
    """
    if not token:
        raise SafetyError(
            "⛔ Token diagnóstico requerido "
            "(entorno forense autorizado בלבד)."
        )

# ── Timeout quirúrgico ────────────────────────────────────────────
TIMEOUT = 6.0

# =========================
# DECLARED UA PROFILES
# =========================
UA_PROFILES = {
    "desktop_chrome": {
        # Identidad primaria
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36 Diagnostic-UA"
        ),

        # Perfil declarado (NO evasión)
        "X-UA-PROFILE": "desktop_chrome",

        # Contexto forense adicional
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",

        # Señales de capa intermedia
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",

        # Declaración explícita de intención
        "X-DIAG-INTENT": "backend-forensics",
        "X-DIAG-VIEW": "desktop",
    },

    "mobile_safari": {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.0 Mobile/15E148 Safari/604.1 Diagnostic-UA"
        ),

        "X-UA-PROFILE": "mobile_safari",

        # Contexto móvil realista (sin engaño)
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, br",

        # Señales de UX / routing
        "Viewport-Width": "390",
        "DPR": "3",

        # Diagnóstico explícito
        "X-DIAG-INTENT": "backend-forensics",
        "X-DIAG-VIEW": "mobile",
    },

    "api_client": {
        "User-Agent": "DiagClient/1.0 (service; backend-forensics)",

        "X-UA-PROFILE": "api_client",

        # Señales API puras
        "Accept": "application/json",
        "Content-Type": "application/json",

        # Semántica de servicio
        "X-REQUEST-TYPE": "service",
        "X-SERVICE-ROLE": "diagnostic-client",

        # Intención explícita
        "X-DIAG-INTENT": "backend-forensics",
        "X-DIAG-VIEW": "api",
    },
}

COMMON_HOSTS = [
    # Raíz canónica
    "{root}",

    # Superficie pública
    "www.{root}",

    # Backend / API
    #"api.{root}",
    #"v1.api.{root}",
    #"v2.api.{root}",

    # Zonas administrativas (a menudo con reglas distintas)
    #"admin.{root}",
    #"dashboard.{root}",

    # Infraestructura interna / legacy
    #"internal.{root}",
    #"intranet.{root}",
    #"services.{root}",

    # Edge / performance
    #"cdn.{root}",
    #"static.{root}",

    # Entornos frecuentes (exposición accidental)
    #"staging.{root}",
    #"dev.{root}",
    #"test.{root}",
]

# =========================
# MODELS
# =========================
@dataclass
class Trigger:
    name: str
    ua_profile: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    note: str = ""

@dataclass
class Observation:
    trigger: str
    ua_profile: str
    status: int
    latency_ms: float
    size: int
    headers: Dict[str, str]

@dataclass
class Delta:
    pair: str
    latency_delta_ms: float
    size_delta: int
    header_diff: List[str]

@dataclass
class Signal:
    key: str
    score: float
    interpretation: str
    evidence: List[str]

# ---- Advanced ----
@dataclass
class TemporalFingerprint:
    mean_ms: float
    stdev_ms: float
    jitter_ms: float

@dataclass
class EntropySignal:
    shannon: float
    normalized: float
    interpretation: str

@dataclass
class ConnectionMeta:
    protocol: str
    tls: Optional[str]
    server_hint: Optional[str]

# =========================
# ROUTE FORENSICS MODELS
# =========================
@dataclass
class RouteProbe:
    path: str
    method: str
    status: int
    latency_ms: float
    entropy_norm: float
    allow: Optional[str]
    note: str = ""

@dataclass
class RouteSignal:
    route: str
    score: float
    interpretation: str
@dataclass
class HostSummary:
    host: str
    routes_tested: int
    mean_latency_ms: float
    entropy_mean: float
    gates_detected: int
    server_hint: Optional[str]

@dataclass
class DomainSignal:
    key: str
    score: float
    interpretation: str
    evidence: List[str]

# =========================
# AUTHORIZED ROUTES
# =========================
COMMON_ROUTES = [
    # Superficie raíz
    "/",

    # Salud y estado (observabilidad)
    "/health",
    "/status",
    #"/healthz",
    #"/ready",
    #"/live",

    # API pública / versionada
    "/api",
    #"/api/v1",
    #"/api/v2",
    #"/api/v3",
    #"/api/status",

    # Autenticación (comportamiento crítico)
    "/login",
    "/auth",
    "/auth/login",
    #"/auth/refresh",
    #"/logout",

    # Telemetría / métricas
    #"/metrics",
    #"/stats",
    #"/telemetry",

    # Debug / diagnóstico (a menudo protegidos… o no)
    #"/debug",
    #"/debug/vars",
    #"/debug/status",
    #"/config",
    #"/config/env",

    # Administración
    "/admin",
    "/admin/login",
    #"/dashboard",

    # Rutas internas / legacy
    "/internal",
    #"/internal/status",
    #"/internal/health",

    # Compatibilidad / frameworks comunes
    #"/actuator",
    #"/actuator/health",
    "/.well-known",
]


METHODS = [
    # =========================
    # Métodos pasivos (base)
    # =========================
    "GET",
    "HEAD",
    "OPTIONS",

    # =========================
    # Métodos semánticos no destructivos
    # =========================
    "TRACE",
    "CONNECT",

    # =========================
    # Métodos informativos / edge-case
    # =========================
    "PROPFIND",   # WebDAV → revela estructura, permisos, depth
    "REPORT",    # DAV / XML APIs → serialización interna
    "SEARCH",    # APIs enterprise / legacy gateways

    # =========================
    # Métodos de control suave (solo detección)
    # =========================
    "CHECKOUT",  # SCM expuesto accidentalmente
    "MKCOL",     # Detecta WebDAV activo (sin usarlo realmente)
]

def build_hosts(domain: str) -> List[str]:
    root = domain.replace("https://","").replace("http://","").strip("/")
    return [h.format(root=root) for h in COMMON_HOSTS]

@contextmanager
def forensic_span(name: str, **attrs):
    with tracer.start_as_current_span(name) as span:
        start = time.time()

        # -----------------------------
        # IDENTIDAD FORENSE BASE
        # -----------------------------
        span.set_attribute("forensic.span", name)
        span.set_attribute("forensic.layer", "backend")
        span.set_attribute("forensic.operator", "surgical")
        span.set_attribute("forensic.instrument", "span_probe")
        span.set_attribute("forensic.visibility", "active")

        # Huella temporal inicial
        span.set_attribute("forensic.start_ts", round(start, 6))

        # -----------------------------
        # ATRIBUTOS DECLARADOS
        # -----------------------------
        for k, v in attrs.items():
            span.set_attribute(k, v)

        try:
            yield span

        finally:
            end = time.time()
            duration = (end - start) * 1000

            # -----------------------------
            # MÉTRICAS DE DURACIÓN
            # -----------------------------
            span.set_attribute("forensic.end_ts", round(end, 6))
            span.set_attribute("forensic.duration_ms", round(duration, 2))

            # -----------------------------
            # CLASIFICACIÓN TEMPORAL
            # -----------------------------
            if duration > 800:
                tclass = "anomalous"
                impact = "critical"
            elif duration > 300:
                tclass = "slow"
                impact = "elevated"
            else:
                tclass = "normal"
                impact = "baseline"

            span.set_attribute("forensic.temporal_class", tclass)
            span.set_attribute("forensic.performance_impact", impact)

            # -----------------------------
            # INTERPRETACIÓN FORENSE
            # -----------------------------
            span.set_attribute(
                "forensic.interpretation",
                f"Execution classified as {tclass} with {impact} impact"
            )

            # Señal para correlación futura
            span.set_attribute("forensic.ready_for_correlation", True)


def mark_signal(span, signal_name: str, score: float, note: str = ""):
    span.set_attribute("signal.name", signal_name)
    span.set_attribute("signal.score", round(score, 3))
    span.set_attribute("signal.note", note)

    severity = (
        "critical" if score >= 0.9 else
        "high" if score >= 0.75 else
        "medium" if score >= 0.5 else
        "low"
    )

    span.set_attribute("signal.severity", severity)
    span.set_attribute("signal.detected", True)

    # Marca forense para correlación futura
    span.set_attribute(
        "forensic.flag",
        f"signal::{signal_name}"
    )

def classify_latency(span, latency_ms: float):
    span.set_attribute("latency.ms", round(latency_ms, 2))

    if latency_ms > 1000:
        span.set_attribute("latency.class", "queue_or_gate")
        span.set_attribute("latency.cause", "auth_gate_or_queue")
        span.set_attribute("latency.impact", "critical")

    elif latency_ms > 500:
        span.set_attribute("latency.class", "backend_processing")
        span.set_attribute("latency.cause", "business_logic")
        span.set_attribute("latency.impact", "high")

    elif latency_ms > 250:
        span.set_attribute("latency.class", "upstream_dependency")
        span.set_attribute("latency.cause", "service_chain")
        span.set_attribute("latency.impact", "medium")

    else:
        span.set_attribute("latency.class", "network_or_cache")
        span.set_attribute("latency.cause", "edge_or_cache")
        span.set_attribute("latency.impact", "low")



def backend_fingerprint(span, meta):
    # Presencia básica
    if not meta:
        span.set_attribute("backend.present", False)
        span.set_attribute("backend.visibility", "absent")
        return

    span.set_attribute("backend.present", True)
    span.set_attribute("backend.visibility", "observable")

    # -----------------------------
    # SERVER HINT (huella primaria)
    # -----------------------------
    if meta.server_hint:
        server = meta.server_hint
        hint = server.lower()

        span.set_attribute("backend.server_hint", server)
        span.set_attribute("backend.fingerprint.source", "server_header")

        # Clasificación heurística (no destructiva)
        if "nginx" in hint:
            btype = "reverse_proxy"
        elif "cloudflare" in hint or "cf-" in hint:
            btype = "cdn_waf"
        elif "akamai" in hint:
            btype = "cdn"
        elif "apache" in hint:
            btype = "application_server"
        elif "gunicorn" in hint or "uwsgi" in hint:
            btype = "python_app_server"
        else:
            btype = "unknown"

        span.set_attribute("backend.type", btype)
        span.set_attribute("backend.classification.confidence", "heuristic")

        # Señal interpretativa (lectura humana)
        span.set_attribute(
            "backend.interpretation",
            f"Tráfico servido vía {btype.replace('_', ' ')}"
        )

    else:
        span.set_attribute("backend.server_hint", "hidden")
        span.set_attribute("backend.fingerprint.source", "none")
        span.set_attribute("backend.type", "opaque")

    # -----------------------------
    # TLS / CIFRADO (huella canal)
    # -----------------------------
    if meta.tls:
        span.set_attribute("backend.tls", meta.tls)
        span.set_attribute("backend.encrypted", True)
        span.set_attribute("backend.channel.security", "encrypted")
    else:
        span.set_attribute("backend.encrypted", False)
        span.set_attribute("backend.channel.security", "plaintext_or_terminated")

    # -----------------------------
    # CLASIFICACIÓN FORENSE FINAL
    # -----------------------------
    span.set_attribute(
        "backend.forensic.summary",
        "edge_or_proxy"
        if span.attributes.get("backend.type") in ("cdn_waf", "cdn", "reverse_proxy")
        else "origin_or_app_layer"
    )

# =========================
# UTILS 
# =========================
def probe_route(base: str, path: str, token: str, method: str) -> RouteProbe:
    url = base.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {token}",
        "X-DIAG-MODE": "true",
        "X-FORENSIC-ROUTE": path,
    }

    jitter_sleep(0)

    # 🔬 SPAN FORENSE VIVO 
    with forensic_span(
        "probe.route",
        target=url,
        method=method,
        route=path,
    ) as span:

        start = time.time()

        try:
            r = requests.request(
                method,
                url,
                headers=headers,
                timeout=TIMEOUT,
            )

            latency = (time.time() - start) * 1000.0
            span.set_attribute("http.status_code", r.status_code)
            span.set_attribute("http.latency_ms", round(latency, 2))

            # ⏱️ CLASIFICACIÓN QUIRÚRGICA DE LATENCIA
            classify_latency(span, latency)

            # 🧬 ENTROPÍA FORENSE
            ent_sig = entropy_signal(r.content) if r.content else EntropySignal(0, 0.0, "vacío")
            span.set_attribute("entropy.raw", round(ent_sig.normalized, 3))
            span.set_attribute("entropy.norm", round(ent_sig.normalized, 3))
            span.set_attribute("entropy.interpretation", ent_sig.interpretation)

            # 🚨 SEÑAL SI ENTROPÍA CAMBIA DEMASIADO
            if ent_sig.normalized > 0.75:
                mark_signal(
                    span,
                    "high_entropy_response",
                    ent_sig.normalized,
                    ent_sig.interpretation,
                )

            # 🔐 FINGERPRINT BACKEND
            meta = connection_meta(r)
            backend_fingerprint(span, meta)

            allow = r.headers.get("Allow")

            return RouteProbe(
                path=path,
                method=method,
                status=r.status_code,
                latency_ms=latency,
                entropy_norm=ent_sig.normalized,
                allow=allow,
            )

        except requests.RequestException as e:
            span.set_attribute("error", True)
            span.set_attribute("error.detail", str(e))

            mark_signal(
                span,
                "request_failure",
                0.9,
                "Fallo de comunicación backend",
            )

            return RouteProbe(
                path=path,
                method=method,
                status=0,
                latency_ms=0.0,
                entropy_norm=0.0,
                allow=None,
                note=str(e),
            )

def probe_host_route(scheme: str, host: str, path: str, token: str, method: str):
    url = f"{scheme}://{host}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-DIAG-MODE": "true",
        "X-FORENSIC-DOMAIN": host,
        "X-FORENSIC-PATH": path,
        "Host": host,
    }

    jitter_sleep(0)

    t0 = time.perf_counter()
    try:
        r = requests.request(method, url, headers=headers, timeout=TIMEOUT)
        t1 = time.perf_counter()

        lat = (t1 - t0) * 1000.0

        # --- Entropía backend
        ent = entropy_signal(r.content).normalized if r.content else 0.0

        # --- Metadatos conexión (ya existentes)
        meta = connection_meta(r)

        # --- Micro señal implícita (no cambia retorno)
        if meta and meta.server_hint and "cloud" in meta.server_hint.lower():
            meta.server_hint += " (edge?)"

        return r.status_code, lat, ent, meta

    except requests.Timeout:
        return 0, TIMEOUT * 1000.0, 0.0, None
    except requests.RequestException:
        return 0, 0.0, 0.0, None


def jitter_sleep(i: int):
    """
    Micro-jitter diagnóstico:
    - Simula latido humano
    - Introduce variabilidad controlada
    - Evita patrones mecánicos
    """
    base = 0.12
    slope = 0.028
    micro = (i % 3) * 0.007
    time.sleep(base + (i * slope) + micro)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    n = len(data)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def entropy_signal(resp: bytes) -> EntropySignal:
    raw = shannon_entropy(resp)
    norm = min(1.0, raw / 8.0)

    interp = (
        "Respuesta rígida / plantilla / WAF / CDN edge"
        if norm < 0.35 else
        "Respuesta estructurada con variación mínima"
        if norm < 0.55 else
        "Respuesta semi-dinámica (backend condicionado)"
        if norm < 0.75 else
        "Respuesta altamente dinámica / data-driven"
    )

    return EntropySignal(raw, norm, interp)

def temporal_fingerprint(samples: List[float]) -> TemporalFingerprint:
    if len(samples) < 2:
        return TemporalFingerprint(samples[0], 0.0, 0.0)

    mean = statistics.mean(samples)
    stdev = statistics.stdev(samples)
    jitter = max(samples) - min(samples)

    return TemporalFingerprint(
        mean_ms=mean,
        stdev_ms=stdev,
        jitter_ms=jitter,
    )


def connection_meta(r: requests.Response) -> ConnectionMeta:
    proto = f"HTTP/{r.raw.version}"
    tls = None
    server = r.headers.get("Server")

    try:
        sock = r.raw._connection.sock
        if hasattr(sock, "cipher"):
            name, version, bits = sock.cipher()
            tls = f"{name} ({bits} bits)"
    except Exception:
        pass

    return ConnectionMeta(
        protocol=proto,
        tls=tls,
        server_hint=server,
    )



def map_routes(base: str, token: str, routes: List[str]) -> List[RouteProbe]:
    probes: List[RouteProbe] = []

    with tracer.start_as_current_span("route-forensic-map"):
        for i, path in enumerate(routes):
            for m in METHODS:
                jitter_sleep(i)
                probes.append(
                    probe_route(base, path, token, m)
                )

    return probes


# =========================
# REQUEST (BISTURÍ)
# =========================
def send(url: str, token: str, t: Trigger, samples: int = 3
         ) -> Tuple[Observation, TemporalFingerprint, EntropySignal, ConnectionMeta]:
    base_headers = {
        "Authorization": f"Bearer {token}",
        "X-DIAG-MODE": "true",
        "X-FORENSIC-BACKEND": t.name,
    }
    ua = UA_PROFILES[t.ua_profile]
    headers = {**base_headers, **ua, **t.headers}

    latencies: List[float] = []
    last_resp: Optional[requests.Response] = None

    for i in range(samples):
        jitter_sleep(i)
        start = time.time()
        r = requests.get(url, headers=headers, params=t.params, timeout=TIMEOUT)
        latencies.append((time.time() - start) * 1000.0)
        last_resp = r

    tf = temporal_fingerprint(latencies)
    ent = entropy_signal(last_resp.content)
    meta = connection_meta(last_resp)

    obs = Observation(
        trigger=t.name,
        ua_profile=t.ua_profile,
        status=last_resp.status_code,
        latency_ms=tf.mean_ms,
        size=len(last_resp.content),
        headers=dict(last_resp.headers),
    )
    return obs, tf, ent, meta

# =========================
# DIFFERENTIAL ENGINE
# =========================
def header_diff(a: Dict[str,str], b: Dict[str,str]) -> List[str]:
    diffs = []
    keys = set(a) | set(b)

    for k in keys:
        va, vb = a.get(k), b.get(k)

        if va == vb:
            continue

        lk = k.lower()

        # Normalización semántica
        if lk in ("date", "expires", "age"):
            diffs.append(f"{k}:temporal")
        elif lk.startswith(("cf-", "x-cache", "x-served-by", "via")):
            diffs.append(f"{k}:edge-layer")
        elif lk in ("content-type", "content-encoding"):
            diffs.append(f"{k}:representation")
        elif lk in ("set-cookie",):
            diffs.append(f"{k}:state")
        elif lk in ("server", "x-powered-by"):
            diffs.append(f"{k}:backend-fingerprint")
        else:
            diffs.append(k)

    return diffs

def deltas(obs: List[Observation]) -> List[Delta]:
    out: List[Delta] = []

    for i in range(len(obs) - 1):
        a, b = obs[i], obs[i + 1]

        latency_delta = b.latency_ms - a.latency_ms
        size_delta = b.size - a.size

        # Umbraliza micro-ruido
        if abs(latency_delta) < 5:
            latency_delta = 0
        if abs(size_delta) < 8:
            size_delta = 0

        out.append(Delta(
            pair=f"{a.trigger}/{a.ua_profile} → {b.trigger}/{b.ua_profile}",
            latency_delta_ms=latency_delta,
            size_delta=size_delta,
            header_diff=header_diff(a.headers, b.headers),
        ))

    return out


# =========================
# HEURISTICS (QUIRÚRGICAS)
# =========================
def h_ua_execution_path(ds: List[Delta]) -> Optional[Signal]:
    swings = [d.latency_delta_ms for d in ds if abs(d.latency_delta_ms) > 120]
    if not swings:
        return None

    mean_swing = sum(abs(s) for s in swings) / len(swings)
    severity = min(1.0, mean_swing / 400.0)

    return Signal(
        "ua_dependent_execution_path",
        severity,
        "El backend ejecuta rutas lógicas distintas según UA declarado.",
        [f"Δlat={round(s,1)}ms" for s in swings[:6]],
    )


def h_representation_switch(ds: List[Delta]) -> Optional[Signal]:
    shifts = [d for d in ds if abs(d.size_delta) > 96]
    if not shifts:
        return None

    avg_shift = sum(abs(d.size_delta) for d in shifts) / len(shifts)
    score = min(1.0, avg_shift / 800.0)

    return Signal(
        "representation_switch",
        score,
        "Cambio de serialización/plantilla según trigger o UA.",
        [f"{d.pair}: Δsize={d.size_delta}" for d in shifts[:6]],
    )


def h_header_semantics(ds: List[Delta]) -> Optional[Signal]:
    hits = []
    for d in ds:
        for k in d.header_diff:
            lk = k.lower()
            if lk.startswith(("vary", "x-cache", "cf-cache", "content-type", "server")):
                hits.append(f"{d.pair}:{k}")

    if not hits:
        return None

    score = min(1.0, len(hits) / max(1, len(ds)))

    return Signal(
        "semantic_header_variance",
        score,
        "Capas HTTP/backend alteran semántica bajo triggers controlados.",
        hits[:8],
    )


def h_temporal_routing(tfps: List[TemporalFingerprint]) -> Optional[Signal]:
    jitters = [t.jitter_ms for t in tfps if t.jitter_ms > 0]
    if not jitters or max(jitters) < 80:
        return None

    spread = max(jitters) - min(jitters)
    score = min(1.0, spread / 350.0)

    return Signal(
        "temporal_backend_routing",
        score,
        "Variación temporal sugiere colas, balanceadores o rutas asíncronas.",
        [f"jitter={round(j,1)}ms" for j in jitters[:6]],
    )

def h_route_gate(probes: List[RouteProbe]) -> List[RouteSignal]:
    sigs: List[RouteSignal] = []
    by_route = {}
    for p in probes:
        by_route.setdefault(p.path, []).append(p)

    for path, ps in by_route.items():
        statuses = {p.status for p in ps}

        # --- Gate lógico
        if statuses & {401,403} and 200 not in statuses:
            sigs.append(RouteSignal(
                path, 0.85,
                "Ruta protegida por gate lógico (auth/role)."
            ))

        # --- Router revela Allow
        if 405 in statuses and any(p.allow for p in ps):
            sigs.append(RouteSignal(
                path, 0.7,
                "Router expone métodos permitidos (Allow)."
            ))

        # --- Cambio de serialización por método
        ents = [p.entropy_norm for p in ps if p.entropy_norm > 0]
        if ents and (max(ents) - min(ents)) > 0.3:
            sigs.append(RouteSignal(
                path, 0.9,
                "Serialización cambia según método → capas internas distintas."
            ))

        # --- Ruta fantasma 
        if statuses == {204} or (statuses == {200} and max(ents or [0]) < 0.05):
            sigs.append(RouteSignal(
                path, 0.6,
                "Ruta liviana / placeholder / health-like."
            ))

    return sigs

HEURISTICS = [h_ua_execution_path, h_representation_switch, h_header_semantics]

def domain_forensics(base_url: str, token: str, routes: List[str]):
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    hosts = build_hosts(parsed.netloc)

    host_summaries: List[HostSummary] = []
    signals: List[DomainSignal] = []

    # --- acumuladores globales para correlación ---
    host_latency_profiles = {}
    host_entropy_profiles = {}

    for host in hosts:
        lats, ents, gates, servers = [], [], 0, set()
        tested = 0
        route_lat_map = {}
        route_ent_map = {}

        for path in routes:
            route_lats = []
            route_ents = []

            for m in METHODS:
                status, lat, ent, meta = probe_host_route(
                    scheme, host, path, token, m
                )
                tested += 1

                if status in (401, 403):
                    gates += 1

                if lat:
                    lats.append(lat)
                    route_lats.append(lat)

                if ent:
                    ents.append(ent)
                    route_ents.append(ent)

                if meta and meta.server_hint:
                    servers.add(meta.server_hint)

            # --- perfil por ruta (intra-host) ---
            if route_lats:
                route_lat_map[path] = statistics.mean(route_lats)
            if route_ents:
                route_ent_map[path] = statistics.mean(route_ents)

        if not lats:
            continue

        mean_lat = statistics.mean(lats)
        mean_ent = statistics.mean(ents) if ents else 0.0

        host_latency_profiles[host] = route_lat_map
        host_entropy_profiles[host] = route_ent_map

        host_summaries.append(HostSummary(
            host=host,
            routes_tested=tested,
            mean_latency_ms=mean_lat,
            entropy_mean=mean_ent,
            gates_detected=gates,
            server_hint=", ".join(sorted(servers)) if servers else None
        ))

        # ===============================
        # 🔬 HEURÍSTICAS INTRA-HOST
        # ===============================

        if route_lat_map:
            spread = max(route_lat_map.values()) - min(route_lat_map.values())
            if spread > 220:
                signals.append(DomainSignal(
                    "intra_host_route_variance",
                    0.7,
                    f"El host {host} ejecuta rutas con costes backend muy distintos.",
                    [f"{p}:{round(v,1)}ms" for p,v in route_lat_map.items()]
                ))

        if route_ent_map:
            ent_spread = max(route_ent_map.values()) - min(route_ent_map.values())
            if ent_spread > 0.35:
                signals.append(DomainSignal(
                    "dynamic_serialization_by_route",
                    0.6,
                    f"Serialización variable por ruta en {host}.",
                    [f"{p}:{round(v,2)}" for p,v in route_ent_map.items()]
                ))

    # ===============================
    # 🔬 HEURÍSTICAS INTER-HOST
    # ===============================

    if len(host_summaries) >= 2:
        latencies = [h.mean_latency_ms for h in host_summaries]
        entropies = [h.entropy_mean for h in host_summaries]

        if max(latencies) - min(latencies) > 180:
            signals.append(DomainSignal(
                "multi_backend_routing",
                0.9,
                "Hosts del mismo dominio enrutan a backends distintos.",
                [f"{h.host}:{round(h.mean_latency_ms,1)}ms" for h in host_summaries]
            ))

        if max(entropies) - min(entropies) > 0.4:
            signals.append(DomainSignal(
                "cross_host_representation_divergence",
                0.75,
                "La representación de datos cambia significativamente entre hosts.",
                [f"{h.host}:{round(h.entropy_mean,2)}" for h in host_summaries]
            ))

    return host_summaries, signals


# =========================
# UI (NEON CRYSTAL SKIN)
# =========================

NEON_Y = "bold bright_yellow"
NEON_P = "bold magenta"
NEON_G = "bold bright_green"
NEON_B = "bold bright_cyan"
NEON_R = "bold bright_red"
DIM_C  = "dim cyan"

def neon_alert(text: str, level: str = "critical"):
    styles = {
        "critical": ("bold bright_red", "bright_red"),
        "high": ("bold bright_yellow", "yellow"),
        "medium": ("bold bright_magenta", "magenta"),
    }

    txt_style, border = styles.get(level, ("bold red", "red"))

    console.print(
        Panel.fit(
            f"[{txt_style}]⚠ {text} ⚠[/{txt_style}]",
            border_style=border,
            padding=(1, 4),
        )
    )


def _typewriter(renderable, delay=0.015):
    text = renderable.renderable
    buffer = ""
    with Live("", refresh_per_second=30, console=console) as live:
        for char in text:
            buffer += char
            live.update(buffer)
            sleep(delay)


def header():
    panel = Panel.fit(
        f"[{NEON_P}]FORENSIC BACKEND · BISTURÍ[{NEON_P}]\n"
        f"[{DIM_C}]Active Diagnostics · Temporal Fingerprints · Entropy Signals[{DIM_C}]\n\n"
        f"[italic {NEON_Y}]Silent like a ninja.[/italic {NEON_Y}]\n"
        f"[italic {NEON_Y}]Precise like a hunter.[/italic {NEON_Y}]\n"
        f"[italic {NEON_Y}]Patient like forensic truth.[/italic {NEON_Y}]\n\n"
        f"[bold {NEON_P}]By Makaveli[/bold {NEON_P}]",
        title=f"[{NEON_Y}]Authorized Diagnostic Mode[{NEON_Y}]",
        border_style=NEON_B
    )

    _typewriter(panel)


def table_routes(probes: List[RouteProbe]):
    t = Table(
        title=f"[{NEON_B}]Mapa Forense de Rutas[{NEON_B}]",
        header_style=NEON_P,
        border_style=NEON_B,
        show_lines=True
    )
    t.add_column("Ruta", style=NEON_G)
    t.add_column("Método", style=NEON_Y)
    t.add_column("Status", style=NEON_R)
    t.add_column("Lat(ms)", style=NEON_B, justify="right")
    t.add_column("Entropy", style=NEON_P, justify="right")
    t.add_column("Allow", style=NEON_G)

    for p in probes:
        t.add_row(
            p.path,
            p.method,
            str(p.status),
            f"{p.latency_ms:.1f}",
            f"{p.entropy_norm:.2f}",
            p.allow or "-"
        )
    console.print(t)

def table_route_signals(sigs: List[RouteSignal]):
    if not sigs:
        console.print(f"[{NEON_G}]✔ Sin señales forenses de rutas.[/{NEON_G}]")
        return

    t = Table(
        title=f"[{NEON_R}]Señales Reveladas · Rutas[{NEON_R}]",
        header_style=NEON_R,
        border_style=NEON_R,
        show_lines=True
    )
    t.add_column("Ruta", style=NEON_G)
    t.add_column("Score", style=NEON_Y, justify="right")
    t.add_column("Interpretación", style=NEON_P)

    for s in sigs:
        t.add_row(s.route, f"{s.score:.2f}", s.interpretation)
    console.print(t)

def table_obs(obs: List[Observation]):
    t = Table(
        title=f"[{NEON_B}]Observaciones Activas[{NEON_B}]",
        header_style=NEON_P,
        border_style=NEON_B,
        show_lines=True
    )
    t.add_column("Trigger", style=NEON_Y)
    t.add_column("UA", style=NEON_P)
    t.add_column("Status", style=NEON_R)
    t.add_column("Latency(ms)", style=NEON_B, justify="right")
    t.add_column("Size", style=NEON_G, justify="right")

    for o in obs:
        t.add_row(
            o.trigger,
            o.ua_profile,
            str(o.status),
            f"{o.latency_ms:.1f}",
            str(o.size)
        )
    console.print(t)

def table_deltas(ds: List[Delta]):
    t = Table(
        title=f"[{NEON_P}]Deltas Forenses[{NEON_P}]",
        header_style=NEON_P,
        border_style=NEON_P,
        show_lines=True
    )
    t.add_column("Par", style=NEON_G)
    t.add_column("Δ Lat(ms)", style=NEON_B, justify="right")
    t.add_column("Δ Size", style=NEON_Y, justify="right")
    t.add_column("Headers Dif.", style=NEON_R)

    for d in ds:
        t.add_row(
            d.pair,
            f"{d.latency_delta_ms:.1f}",
            str(d.size_delta),
            ", ".join(d.header_diff[:6])
        )
    console.print(t)

def table_sigs(sigs: List[Signal]):
    if not sigs:
        console.print(f"[{NEON_G}]✔ Sin triggers causales relevantes.[/{NEON_G}]")
        return

    t = Table(
        title=f"[{NEON_R}]Señales Reveladas[{NEON_R}]",
        header_style=NEON_R,
        border_style=NEON_R,
        show_lines=True
    )
    t.add_column("Key", style=NEON_G)
    t.add_column("Score", style=NEON_Y, justify="right")
    t.add_column("Interpretación", style=NEON_P)

    for s in sigs:
        t.add_row(s.key, f"{s.score:.2f}", s.interpretation)
    console.print(t)

def panel_adv(tfps: List[TemporalFingerprint], ents: List[EntropySignal], metas: List[ConnectionMeta]):
    lines = []
    for i, (t, e, m) in enumerate(zip(tfps, ents, metas)):
        lines.append(
            f"[{NEON_P}]#{i+1}[/{NEON_P}] "
            f"[{NEON_B}]μ={t.mean_ms:.1f}ms σ={t.stdev_ms:.1f}ms jitter={t.jitter_ms:.1f}ms[/{NEON_B}] | "
            f"[{NEON_Y}]entropy={e.normalized:.2f}[/{NEON_Y}] "
            f"[{DIM_C}]({e.interpretation})[/{DIM_C}] | "
            f"[{NEON_G}]{m.protocol}[/{NEON_G}] "
            f"[{NEON_P}]tls={m.tls or 'n/a'}[/{NEON_P}] "
            f"[{NEON_R}]server={m.server_hint or 'n/a'}[/{NEON_R}]"
        )

    console.print(
        Panel.fit(
            "\n".join(lines),
            title=f"[{NEON_B}]Huella Avanzada[{NEON_B}]",
            border_style=NEON_B
        )
    )

def table_domain(hosts: List[HostSummary]):
    t = Table(
        title=f"[{NEON_B}]Dominio · Anatomía Forense[{NEON_B}]",
        header_style=NEON_P,
        border_style=NEON_B,
        show_lines=True
    )
    t.add_column("Host", style=NEON_G)
    t.add_column("Rutas", style=NEON_Y, justify="right")
    t.add_column("Lat μ(ms)", style=NEON_B, justify="right")
    t.add_column("Entropy μ", style=NEON_P, justify="right")
    t.add_column("Gates", style=NEON_R, justify="right")
    t.add_column("Server", style=NEON_G)

    for h in hosts:
        t.add_row(
            h.host,
            str(h.routes_tested),
            f"{h.mean_latency_ms:.1f}",
            f"{h.entropy_mean:.2f}",
            str(h.gates_detected),
            h.server_hint or "-"
        )
    console.print(t)

def table_domain_signals(sigs: List[DomainSignal]):
    if not sigs:
        console.print(f"[{NEON_G}]✔ Dominio consistente sin señales críticas.[/{NEON_G}]")
        return

    t = Table(
        title=f"[{NEON_R}]Señales Forenses de Dominio[{NEON_R}]",
        header_style=NEON_R,
        border_style=NEON_R,
        show_lines=True
    )
    t.add_column("Key", style=NEON_G)
    t.add_column("Score", style=NEON_Y, justify="right")
    t.add_column("Interpretación", style=NEON_P)

    for s in sigs:
        t.add_row(s.key, f"{s.score:.2f}", s.interpretation)
    console.print(t)


# =========================
# RUN 
# =========================
def run():
    header()
    console.print("[bold neon_green]🔥 BIENVENIDO AL FORENSIC SURGICAL ENGINE 🔥[/bold neon_green]\n")
    console.print("[dim]Iniciando análisis con filosofía ninja/hacker...[/dim]\n")
    
    current_url = None
    while True:
        # ---------------------- INGRESO DE URL ----------------------
        if not current_url:
            while True:
                raw_url = Prompt.ask("URL autorizada", default="https://example.com/health")
                parsed = urlparse(raw_url)
                
                # Si no tiene esquema, agregar https://
                if not parsed.scheme:
                    current_url = "https://" + raw_url
                else:
                    current_url = raw_url
                
                # Validar que sea URL correcta
                parsed = urlparse(current_url)
                if all([parsed.scheme in ["http", "https"], parsed.netloc]):
                    console.print(f"[green]✅ URL válida detectada:[/green] [bold]{current_url}[/bold]")
                    break
                else:
                    console.print(f"[red]❌ '{raw_url}' no es una URL válida. Intenta de nuevo.[/red]")

        # ---------------------- INGRESO DE TOKEN ----------------------
        while True:
            try:
                token = Prompt.ask("Token diagnóstico", password=True)
                ensure_authorized(token)
                break
            except Exception as e:
                console.print(f"[red]⚠️ Token inválido: {e}[/red] Intenta de nuevo...")

        # ---------------------- TRIGGERS ----------------------
        triggers = [
            Trigger(name="baseline_desktop", ua_profile="desktop_chrome"),
            Trigger(name="mobile_view", ua_profile="mobile_safari"),
            Trigger(name="service_client", ua_profile="api_client"),
        ]

        observations: List[Observation] = []
        tfps: List[TemporalFingerprint] = []
        ents: List[EntropySignal] = []
        metas: List[ConnectionMeta] = []

        console.print(f"\n[cyan]🔎 Ejecutando análisis para:[/cyan] [bold]{current_url}[/bold]\n")

        # ---------------------- EJECUCIÓN PRINCIPAL ----------------------
        try:
            with tracer.start_as_current_span("forensic-backend-run") as span:
                span.set_attribute("target", current_url)
                for t in track(triggers, description="[magenta]Procesando triggers...[/magenta]"):
                    try:
                        obs, tf, ent, meta = send(current_url, token, t, samples=3)
                        observations.append(obs)
                        tfps.append(tf)
                        ents.append(ent)
                        metas.append(meta)
                    except Exception as e:
                        console.print(f"[red]⚠️ Error en trigger {t.name}: {e}[/red]")
        except Exception as e:
            console.print(f"[bold red]💀 Error crítico en ejecución principal: {e}[/bold red]")
            continue

        ds = deltas(observations)

        table_obs(observations)
        table_deltas(ds)
        panel_adv(tfps, ents, metas)

        sigs: List[Signal] = []
        for h in HEURISTICS:
            try:
                s = h(ds)
                if s: sigs.append(s)
            except Exception as e:
                console.print(f"[red]⚠️ Error en heurística: {e}[/red]")
        ts = h_temporal_routing(tfps)
        if ts: sigs.append(ts)

        table_sigs(sigs)

        console.print(Panel.fit(
            "[dim]Conclusión:[/dim]\n"
            "• Cambios por UA revelan capas (plantillas, routers, caches).\n"
            "• Huella temporal expone colas y rutas.\n"
            "• Entropía distingue SSR/CSR/edge.\n"
            "• Diagnóstico comparativo, ético y accionable.",
            title="[title]Lectura Suprema[/title]"
        ))

        try:
            probes = map_routes(current_url, token, COMMON_ROUTES)
            table_routes(probes)

            route_sigs = h_route_gate(probes)
            table_route_signals(route_sigs)

            hosts, dom_sigs = domain_forensics(current_url, token, COMMON_ROUTES)
            table_domain(hosts)
            table_domain_signals(dom_sigs)
        except Exception as e:
            console.print(f"[red]⚠️ Error en análisis de rutas o dominios: {e}[/red]")

        # ---------------------- MENÚ POST-ANÁLISIS ----------------------
        console.print("\n[bold neon_purple]⚡ Menú Forense Interactivo ⚡[/bold neon_purple]")
        choice = Prompt.ask(
            "¿Qué deseas hacer?",
            choices=["otra URL", "repetir", "salir", "reiniciar completo"],
            default="salir"
        )

        if choice == "salir":
            console.print("\n[bold neon_green]✅ Hasta la próxima, explorador forense![/bold neon_green]")
            break
        elif choice == "repetir":
            console.print("[yellow]♻️ Reiniciando análisis con la misma URL...[/yellow]\n")
            continue
        elif choice == "otra URL":
            console.print("[cyan]🌐 Preparando para una nueva URL...[/cyan]\n")
            current_url = None
            continue
        
if __name__ == "__main__":
    run()
