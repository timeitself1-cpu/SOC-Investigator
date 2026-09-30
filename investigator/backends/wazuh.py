"""Read-only Wazuh backend adapter.

STATUS: implemented against Wazuh's documented interfaces, unit-tested with a
mocked HTTP transport, NOT verified against a live Wazuh deployment by the
author. See README "Wazuh configuration" for what must be confirmed in your lab.

Data sources:
  * Wazuh indexer (OpenSearch API, default port 9200): alerts/events via `_search`.
  * Wazuh server API (default port 55000, optional): agent metadata for host context.

Note: by default Wazuh only indexes events that matched a rule (`wazuh-alerts-*`).
Surrounding telemetry (every Sysmon event) is only queryable if archives are
enabled (`logall_json` + an archives index). Set SOCI_WAZUH_EVENTS_INDEX
accordingly.

Read-only enforcement: every HTTP call goes through `_request`, which only
permits an explicit allowlist of (method, path) pairs: `_search` queries,
token authentication, and GET /agents. No other request can be made.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..config import Settings
from ..errors import ClassifiedError, classify_exception, classify_http_status
from ..models import Alert, HostContext, NormalizedEvent
from .base import EventQuery, severity_from_level
from .normalize import SECURITY_CATEGORIES, SYSMON_CATEGORIES, normalize_wazuh_doc

CATEGORY_EVENT_IDS: dict[str, list[str]] = {
    "process": ["1", "4688"],
    "network": ["3"],
    "process_access": ["10"],
    "file": ["11"],
    "registry": ["12", "13", "14"],
    "dns": ["22"],
    "authentication": ["4624", "4625"],
    "scheduled_task": ["4698"],
}

_INDEX = r"[A-Za-z0-9*._,-]+"
ALLOWED_REQUESTS: list[tuple[str, str, re.Pattern[str]]] = [
    ("indexer", "POST", re.compile(rf"^/{_INDEX}/_search$")),
    ("api", "POST", re.compile(r"^/security/user/authenticate$")),
    ("api", "GET", re.compile(r"^/agents$")),
]


class WazuhConfigError(RuntimeError):
    pass


class WazuhSearchError(ClassifiedError):
    """Search results are incomplete, ambiguous, or malformed."""

    def __init__(self, message: str, kind: str = "partial_results") -> None:
        super().__init__(kind, message)


def _event_ref(hit: dict[str, Any]) -> str:
    doc_id = hit.get("_id")
    if not isinstance(doc_id, str) or not doc_id:
        raise WazuhSearchError("Wazuh hit has no document id")
    index = hit.get("_index")
    if not index:
        return doc_id  # compatibility with older adapters / exported hits
    encode = lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return f"wz1~{encode(index)}~{encode(doc_id)}"


def _decode_ref(ref: str) -> tuple[str | None, str]:
    if not ref.startswith("wz1~"):
        return None, ref
    try:
        _, index, doc_id = ref.split("~")
        decode = lambda value: base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode()
        index, doc_id = decode(index), decode(doc_id)
        # A reference selects one concrete index, never a wildcard or a path.
        if not re.fullmatch(r"[A-Za-z0-9._-]+", index) or not doc_id:
            raise ValueError("invalid reference")
        return index, doc_id
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("invalid Wazuh event reference") from exc


class WazuhBackend:
    name = "wazuh"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        if not settings.wazuh_indexer_url or not settings.wazuh_indexer_user or not settings.wazuh_indexer_password:
            raise WazuhConfigError(
                "Wazuh backend requires SOCI_WAZUH_INDEXER_URL, SOCI_WAZUH_INDEXER_USER and "
                "SOCI_WAZUH_INDEXER_PASSWORD (set them in the environment or in a local .env file)."
            )
        self.s = settings
        verify: bool | str = settings.wazuh_ca_bundle or settings.wazuh_verify_tls
        self._clients = {
            "indexer": httpx.Client(
                base_url=settings.wazuh_indexer_url.rstrip("/"),
                auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password.get_secret_value()),
                verify=verify, timeout=settings.wazuh_timeout, transport=transport,
            )
        }
        if settings.wazuh_api_url and settings.wazuh_api_user and settings.wazuh_api_password:
            self._clients["api"] = httpx.Client(
                base_url=settings.wazuh_api_url.rstrip("/"), verify=verify,
                timeout=settings.wazuh_timeout, transport=transport,
            )
        self._api_token: str | None = None
        # Alerts dropped from the queue because the record could not be parsed.
        self.skipped_alerts = 0

    def __repr__(self) -> str:  # never leak credentials
        return f"WazuhBackend(indexer={self.s.wazuh_indexer_url!r}, api={self.s.wazuh_api_url!r})"

    # -- guarded HTTP ----------------------------------------------------
    def _request(self, target: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if not any(t == target and m == method and p.fullmatch(path) for t, m, p in ALLOWED_REQUESTS):
            raise PermissionError(f"blocked non-allowlisted Wazuh request: {target} {method} {path}")
        client = self._clients.get(target)
        if client is None:
            raise WazuhConfigError(f"Wazuh {target} is not configured")
        try:
            resp = client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            # Transport errors (timeouts, TLS, refused) are classified; the raw
            # message (URLs, library text) is not propagated.
            raise classify_exception(exc) from None
        if resp.status_code >= 400:
            # The body is inspected only for error-type tokens, never copied.
            raise ClassifiedError(classify_http_status(resp.status_code, resp.text),
                                  status_code=resp.status_code)
        return resp

    def _search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        # A wildcard pattern that matches no index (e.g. archives not enabled)
        # would otherwise return HTTP 200 with zero shards and zero hits — which
        # looks exactly like "no activity". Make it an explicit failure.
        resp = self._request("indexer", "POST", f"/{index}/_search", json=body,
                             params={"allow_partial_search_results": "false",
                                     "allow_no_indices": "false", "ignore_unavailable": "false"})
        try:
            data = resp.json()
        except ValueError:
            raise WazuhSearchError("Wazuh returned a non-JSON search response", "invalid_response") from None
        if not isinstance(data, dict):
            raise WazuhSearchError("Wazuh returned an invalid search response", "invalid_response")
        shards = data.get("_shards") or {}
        if isinstance(shards, dict) and shards.get("total") == 0:
            raise WazuhSearchError("The configured index pattern matched no index", "index_missing")
        if data.get("timed_out") or (isinstance(shards, dict) and shards.get("failed", 0)):
            raise WazuhSearchError("Wazuh search timed out or failed on one or more shards", "partial_results")
        hits = (data.get("hits") or {}).get("hits") if isinstance(data.get("hits"), dict) else None
        if not isinstance(hits, list):
            raise WazuhSearchError("Wazuh returned an invalid search response", "invalid_response")
        return hits

    @staticmethod
    def _normalize_hit(hit: dict[str, Any]) -> NormalizedEvent:
        try:
            return WazuhBackend._to_event(hit)
        except ClassifiedError:
            raise
        except (ValueError, TypeError, KeyError) as exc:
            # A record that does not match the expected Windows eventchannel
            # mapping is a mapping problem, reported without its content.
            raise WazuhSearchError("A Wazuh record did not match the expected field mapping",
                                   "invalid_response") from exc

    @staticmethod
    def _to_event(hit: dict[str, Any]) -> NormalizedEvent:
        return normalize_wazuh_doc(hit.get("_source", {}), event_ref=_event_ref(hit))

    # -- query construction (pure; unit tested) --------------------------
    @staticmethod
    def build_query(q: EventQuery) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [
            {"range": {"timestamp": {"gte": q.start.isoformat(), "lte": q.end.isoformat()}}}
        ]
        if q.host:
            filters.append({"term": {"agent.name": q.host}})
        if q.category:
            filters.append(WazuhBackend._category_filter(q.category))
        if q.event_id is not None:
            filters.append({"term": {"data.win.system.eventID": str(q.event_id)}})
        if q.process_guid:
            filters.append({"bool": {"should": [
                {"term": {"data.win.eventdata.processGuid": q.process_guid}},
                {"term": {"data.win.eventdata.processGUID": q.process_guid}},
                {"term": {"data.win.eventdata.sourceProcessGUID": q.process_guid}},
                {"term": {"data.win.eventdata.sourceProcessGuid": q.process_guid}},
            ], "minimum_should_match": 1}})
        if q.parent_process_guid:
            filters.append({"bool": {"should": [
                {"term": {"data.win.eventdata.parentProcessGuid": q.parent_process_guid}},
                {"term": {"data.win.eventdata.parentProcessGUID": q.parent_process_guid}},
            ], "minimum_should_match": 1}})
        must: list[dict[str, Any]] = []
        if q.keyword:
            must.append({"match_phrase": {"full_log": q.keyword}})
        return {
            "size": q.limit,
            "sort": [{"timestamp": {"order": q.order}}],
            "query": {"bool": {"filter": filters, "must": must}},
        }

    @staticmethod
    def _category_filter(category: str) -> dict[str, Any]:
        def group(ids: list[str], provider: dict[str, Any]) -> dict[str, Any]:
            return {"bool": {"filter": [provider, {"terms": {"data.win.system.eventID": ids}}]}}

        sysmon = {"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}}
        security = {"bool": {"should": [
            {"term": {"data.win.system.providerName": "Microsoft-Windows-Security-Auditing"}},
            {"term": {"data.win.system.channel": "Security"}},
        ], "minimum_should_match": 1}}
        branches = []
        for categories, provider in ((SYSMON_CATEGORIES, sysmon), (SECURITY_CATEGORIES, security)):
            ids = [str(event_id) for event_id, value in categories.items() if category == "other" or value == category]
            if ids:
                branches.append(group(ids, provider))
        if category == "other":
            return {"bool": {"must_not": branches}}
        return {"bool": {"should": branches, "minimum_should_match": 1}}

    def _lookup(self, ref: str, patterns: list[str]) -> list[dict[str, Any]]:
        index, doc_id = _decode_ref(ref)
        if index:
            # User/model-supplied references cannot escape configured index scope.
            selectors = [part for pattern in patterns for part in pattern.split(",")]
            included = any(fnmatch.fnmatchcase(index, part) for part in selectors if not part.startswith("-"))
            excluded = any(fnmatch.fnmatchcase(index, part[1:]) for part in selectors if part.startswith("-"))
            if not included or excluded:
                raise ValueError("Wazuh event reference is outside configured indexes")
        else:
            index = ",".join(dict.fromkeys(patterns))
        hits = self._search(index, {"size": 2, "query": {"ids": {"values": [doc_id]}}})
        if len(hits) > 1:
            raise WazuhSearchError("Ambiguous Wazuh document id; use an index-qualified reference from the alert queue")
        return hits

    # -- TelemetryBackend ------------------------------------------------
    def list_alerts(self) -> list[Alert]:
        now = datetime.now(timezone.utc)
        body = {
            "size": 50,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": self.s.wazuh_min_alert_level}}},
                {"range": {"timestamp": {"gte": (now - timedelta(hours=self.s.wazuh_alert_lookback_hours)).isoformat()}}},
            ]}},
        }
        alerts: list[Alert] = []
        skipped = 0
        for hit in self._search(self.s.wazuh_alerts_index, body):
            try:
                alerts.append(self._hit_to_alert(hit))
            except (ClassifiedError, ValueError, TypeError, KeyError):
                # One malformed alert must not hide every other alert.
                skipped += 1
        self.skipped_alerts = skipped
        return alerts

    def _hit_to_alert(self, hit: dict[str, Any]) -> Alert:
        ev = self._normalize_hit(hit)
        return Alert(
            alert_id=ev.event_ref,
            title=(ev.rule_description or f"Wazuh rule {ev.rule_id}")[:300],
            timestamp=ev.timestamp,
            host=ev.host,
            severity=severity_from_level(ev.rule_level),  # type: ignore[arg-type]
            rule_id=ev.rule_id,
            rule_level=ev.rule_level,
            event_ref=ev.event_ref,
            process_guid=ev.process_guid,
            user=ev.user,
            source="wazuh",
        )

    def get_alert(self, alert_id: str) -> Alert | None:
        hits = self._lookup(alert_id, [self.s.wazuh_alerts_index])
        return self._hit_to_alert(hits[0]) if hits else None

    def get_event(self, event_ref: str) -> NormalizedEvent | None:
        hits = self._lookup(event_ref, [self.s.wazuh_events_index, self.s.wazuh_alerts_index])
        return self._normalize_hit(hits[0]) if hits else None

    def search_events(self, query: EventQuery) -> list[NormalizedEvent]:
        return [self._normalize_hit(h) for h in self._search(self.s.wazuh_events_index, self.build_query(query))]

    def coverage_caveats(self) -> list[str]:
        caveats = []
        if self.s.wazuh_events_index.strip() == self.s.wazuh_alerts_index.strip():
            caveats.append("Events are searched in the alerts index: only rule-matched events are searchable; "
                           "surrounding telemetry that did not trigger a rule is invisible to this investigation.")
        caveats.append("Wazuh field mappings are assumed to follow the default Windows eventchannel decoder "
                       "(data.win.system / data.win.eventdata); run `python -m investigator diagnose` to check.")
        return caveats

    def _agents(self, host: str) -> httpx.Response:
        """GET /agents with one token refresh: Wazuh API JWTs expire (default 900 s)."""
        for attempt in (1, 2):
            token = self._token()
            try:
                return self._request("api", "GET", "/agents", params={"name": host},
                                     headers={"Authorization": f"Bearer {token}"})
            except ClassifiedError as exc:
                if exc.kind == "auth" and attempt == 1:
                    self._api_token = None
                    continue
                raise
        raise ClassifiedError("auth")  # pragma: no cover - loop always returns or raises

    def get_host_context(self, host: str) -> HostContext | None:
        if "api" in self._clients:
            resp = self._agents(host)
            try:
                items = resp.json().get("data", {}).get("affected_items", [])
            except (ValueError, AttributeError):
                raise WazuhSearchError("Wazuh API returned an invalid agents response", "invalid_response") from None
            if items:
                a = items[0]
                os_info = a.get("os") or {}
                return HostContext(
                    host=a.get("name", host), ip=a.get("ip"), agent_status=a.get("status"),
                    os=" ".join(str(x) for x in (os_info.get("name"), os_info.get("version")) if x) or None,
                    notes=f"Wazuh agent id {a.get('id')}; groups: {', '.join(a.get('group') or [])}",
                )
        # Fallback: agent fields on the most recent event for the host.
        hits = self._search(self.s.wazuh_alerts_index, {
            "size": 1, "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [{"term": {"agent.name": host}}]}},
        })
        if not hits:
            return None
        agent = hits[0].get("_source", {}).get("agent", {})
        return HostContext(host=agent.get("name", host), ip=agent.get("ip"),
                           notes="Derived from indexed events (Wazuh API not configured).")

    def _token(self) -> str:
        if self._api_token is None:
            s = self.s
            assert s.wazuh_api_user and s.wazuh_api_password
            resp = self._request("api", "POST", "/security/user/authenticate",
                                 auth=(s.wazuh_api_user, s.wazuh_api_password.get_secret_value()))
            try:
                token = resp.json()["data"]["token"]
            except (ValueError, KeyError, TypeError):
                raise WazuhSearchError("Wazuh API returned an invalid token response", "invalid_response") from None
            if not isinstance(token, str) or not token:
                raise WazuhSearchError("Wazuh API returned an empty token", "invalid_response")
            self._api_token = token
        return self._api_token

    # -- diagnostics (read-only; used by `investigator diagnose`) --------
    def probe(self, host: str | None = None) -> list[dict[str, Any]]:
        """Check reachability, auth, index presence, field mapping and archives.

        Every check uses the same allowlisted read-only requests as the agent.
        Returns [{check, ok, kind, detail}] and never raises.
        """
        results: list[dict[str, Any]] = []

        def run(check: str, fn) -> Any:
            try:
                detail = fn()
                results.append({"check": check, "ok": True, "kind": None, "detail": detail})
                return detail
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                c = classify_exception(exc)
                results.append({"check": check, "ok": False, "kind": c.kind, "detail": c.safe_message})
                return None

        now = datetime.now(timezone.utc)
        recent = {"range": {"timestamp": {"gte": (now - timedelta(hours=24)).isoformat()}}}

        def sample(index: str) -> str:
            hits = self._search(index, {"size": 1, "sort": [{"timestamp": {"order": "desc"}}],
                                        "query": {"bool": {"filter": [recent]}}})
            if not hits:
                return "index reachable; no documents in the last 24h"
            src = hits[0].get("_source") or {}
            missing = [f for f in ("timestamp", "agent.name") if self._path(src, f) is None]
            if missing:
                raise WazuhSearchError(f"sample document lacks {', '.join(missing)}", "mapping")
            return "index reachable; sample document has timestamp and agent.name"

        run("alerts index reachable + auth", lambda: sample(self.s.wazuh_alerts_index))
        if self.s.wazuh_events_index != self.s.wazuh_alerts_index:
            run("events (archives) index present", lambda: sample(self.s.wazuh_events_index))
        else:
            results.append({"check": "events (archives) index present", "ok": False, "kind": "index_missing",
                            "detail": "events index equals the alerts index; only rule-matched events are searchable"})

        def sysmon() -> str:
            filters = [recent, {"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}}]
            if host:
                filters.append({"term": {"agent.name": host}})
            hits = self._search(self.s.wazuh_events_index, {"size": 1, "query": {"bool": {"filter": filters}}})
            if not hits:
                raise WazuhSearchError("no Sysmon events matched in the last 24h (check Sysmon forwarding, "
                                       "providerName mapping, or agent.name)", "mapping")
            ed = ((hits[0].get("_source") or {}).get("data") or {}).get("win", {}).get("eventdata") or {}
            keys = sorted(k for k in ed if k in {"image", "processGuid", "parentProcessGuid", "commandLine"})
            return f"Sysmon events present; eventdata keys seen: {', '.join(keys) or 'none of the expected'}"

        run("Sysmon telemetry and field names", sysmon)
        if "api" in self._clients:
            run("server API auth", lambda: (self._token(), "token issued")[1])
        return results

    @staticmethod
    def _path(d: dict[str, Any], path: str) -> Any:
        cur: Any = d
        for part in path.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
