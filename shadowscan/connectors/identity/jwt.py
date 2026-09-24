"""JWT analysis: is this token held by a human, a service, or an agent acting on behalf of someone?

Tokens are decoded *without* verification by default (optionally verified
against a JWKS URL). The token itself is never stored; findings reference a
truncated SHA-256 of it.

Signals evaluated:

* issuer family (Okta, Entra, Google, Auth0, Cognito, Keycloak, SPIFFE, custom)
* machine identity: ``gty=client-credentials``, Entra ``idtyp=app`` / ``appid``
  without user claims, Okta ``cid == sub``, Google service-account emails,
  Cognito access tokens without ``username``, SPIFFE subjects
* delegation / on-behalf-of: RFC 8693 ``act`` / ``may_act`` chains, ``azp != aud``
* agent hints in claims (``agent_id``, ``agent``, ``bot``, ``client_name`` matching
  AI product names), audiences that are LLM / agent APIs
* privilege: scopes / roles / permissions classified by policy signatures
* hygiene: lifetime > 24h, no ``exp``, ``alg=none``, symmetric algs on public issuers

Input: ``tokens: [...]`` in config, ``input`` file (one token per line, JSON list,
or JSON objects with a ``token`` field), or the CLI ``shadowscan jwt`` command.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorError, _NoDump
from shadowscan.connectors.common import (
    apply_matches,
    classify_permissions,
    domain_matches,
    finalize,
    name_matches,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.jwks import fetch_jwks, verification_algorithms, verify_against_jwks
from shadowscan.utils.text import parse_timestamp, to_iso

_JWT_RX = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")
USER_CLAIMS = ("upn", "preferred_username", "email", "unique_name", "name", "given_name", "family_name", "username", "cognito:username", "oid_user")
AGENT_CLAIM_KEYS = ("agent_id", "agent", "agent_name", "agentid", "x-agent-id", "bot", "bot_id", "client_name", "app_displayname", "azp_name", "workload", "spiffe_id", "delegation", "on_behalf_of", "obo", "actor", "act", "may_act", "purpose", "tool", "tools")


class JwtConnector(BaseConnector, _NoDump):
    name: ClassVar[str] = "identity.jwt"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "jwt"
    description: ClassVar[str] = "Classify JWTs as human, service or agent (delegated) identities and assess their privileges."
    config_keys: ClassVar[dict[str, str]] = {
        "tokens": "list of JWT strings",
        "jwks_url": "optional operator-trusted JWKS endpoint for signature verification",
        "expected_issuer": "optional exact expected issuer; otherwise signature-only verification",
        "allowed_algorithms": "optional nonempty subset of RS256, ES256, EdDSA, PS256",
        "input": "file with one token per line or JSON list / objects with `token`",
    }
    offline_formats: ClassVar[str] = "text (one JWT per line) / JSON"

    def collect(self) -> Iterable[dict[str, Any]]:
        tokens = self.ctx.get("tokens") or []
        if not tokens:
            raise ConnectorError("identity.jwt: provide 'tokens' or an input file")
        if not isinstance(tokens, list):
            raise ConnectorError("identity.jwt: tokens must be a list")
        for t in tokens:
            yield {"token": t}

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        suffixes = {".json", ".jsonl", ".ndjson", ".txt", ".jwt"}
        for source in self._offline_files(path, suffixes):
            text = self._read_offline_text(source)
            if text is None:
                continue
            stripped = text.strip()
            if not stripped:
                self.ctx.error("identity.jwt: empty token export; use [] for an empty token list")
                continue
            if source.suffix.lower() in {".jsonl", ".ndjson"}:
                for number, line in enumerate(text.splitlines(), 1):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                    except (json.JSONDecodeError, RecursionError, ValueError):
                        self.ctx.error(f"identity.jwt: invalid JSON record at line {number}")
                        continue
                    yield from self._token_records(data)
            elif source.suffix.lower() == ".json" or stripped.startswith(("[", "{")):
                try:
                    data = json.loads(stripped)
                except (json.JSONDecodeError, RecursionError, ValueError):
                    self.ctx.error("identity.jwt: invalid JSON token export")
                    continue
                yield from self._token_records(data)
            else:
                for number, line in enumerate(text.splitlines(), 1):
                    if not line.strip():
                        continue
                    token = line.strip().strip('"').removeprefix("Bearer ").strip()
                    if _JWT_RX.fullmatch(token):
                        yield {"token": token}
                    else:
                        self.ctx.error(f"identity.jwt: invalid token record at line {number}")

    def _token_records(self, data: Any) -> Iterator[dict[str, Any]]:
        records = data if isinstance(data, list) else [data]
        for number, record in enumerate(records, 1):
            if isinstance(record, str):
                yield {"token": record}
            elif self._valid_record(record):
                yield record
            else:
                self.ctx.error(f"identity.jwt: invalid token export record {number}")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        jwks_url = self.ctx.get("jwks_url")
        try:
            verification_algorithms(self.ctx.get("allowed_algorithms"))
            expected_issuer = self.ctx.get("expected_issuer")
            if expected_issuer is not None and (not isinstance(expected_issuer, str) or not expected_issuer):
                raise ValueError("expected_issuer must be a nonempty string")
        except ValueError as exc:
            raise ConnectorError(f"identity.jwt: {exc}") from exc
        self._jwks_cache: dict[str, Any] = {}
        for rec in records:
            token = rec.get("token") or rec.get("jwt") or rec.get("access_token") or rec.get("id_token")
            if not isinstance(token, str) or not _JWT_RX.fullmatch(token.strip()):
                self.ctx.error("identity.jwt: record is missing a valid JWT token")
                continue
            self.ctx.examined()
            try:
                f = self.analyze_token(str(token).strip(), jwks_url=jwks_url, context=rec.get("context") or rec.get("source"))
            except (ValueError, TypeError, OverflowError, RecursionError, KeyError, MatchTimeoutError) as exc:
                # Hostile claims (huge numbers, odd types) must not stop the
                # analysis of every later token in the input.
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"identity.jwt: token analysis failed ({type(exc).__name__}){detail}")
                continue
            if f:
                yield f

    def _jwks_document(self, jwks_url: str) -> dict[str, Any]:
        """Fetch each configured key set once per run, including its failure."""
        if not hasattr(self, "_jwks_cache"):
            self._jwks_cache = {}
        cached = self._jwks_cache.get(jwks_url)
        if cached is None:
            try:
                cached = fetch_jwks(jwks_url)
            except Exception as exc:  # noqa: BLE001 - remembered so every token reports the same outcome
                cached = exc
            self._jwks_cache[jwks_url] = cached
        if isinstance(cached, BaseException):
            # Re-raising one cached exception otherwise retains a traceback
            # frame for every token analyzed after an unavailable key set.
            raise cached.with_traceback(None)
        return cached

    # -------------------------------------------------------------- analysis
    def analyze_token(self, token: str, jwks_url: str | None = None, context: str | None = None) -> Finding | None:
        import jwt as pyjwt

        if len(token) > 131072:
            self.ctx.warn("identity.jwt: token exceeds analysis byte limit")
            return None
        try:
            header = pyjwt.get_unverified_header(token)
            claims = pyjwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
        except (pyjwt.PyJWTError, RecursionError, ValueError) as exc:
            self.ctx.warn(f"identity.jwt: cannot decode token ({type(exc).__name__})")
            return None
        verified: bool | None = None
        if jwks_url:
            try:
                verified = verify_against_jwks(
                    token,
                    jwks_url,
                    header,
                    expected_issuer=self.ctx.get("expected_issuer"),
                    allowed_algorithms=self.ctx.get("allowed_algorithms"),
                    document_loader=self._jwks_document,
                )
            except Exception as exc:  # noqa: BLE001
                verified = False
                self.ctx.warn(f"identity.jwt: signature verification failed ({type(exc).__name__})")

        digest = hashlib.sha256(token.encode()).hexdigest()[:16]
        iss = str(claims.get("iss") or "")
        sub = str(claims.get("sub") or "")
        aud = claims.get("aud")
        aud_list = [str(a) for a in (aud if isinstance(aud, list) else [aud] if aud else [])]
        family = _issuer_family(iss, claims)
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=Kind.TOKEN,
            title="",
            resource=f"jwt:{digest}",
            resource_type="jwt",
            provider=family,
            account=iss or None,
        )
        reasons: list[str] = []
        identity_type = "human"

        has_user = any(k in claims for k in USER_CLAIMS)
        if claims.get("gty") == "client-credentials":
            identity_type = "service"
            reasons.append("Auth0 gty=client-credentials")
        if str(claims.get("idtyp", "")).lower() == "app":
            identity_type = "service"
            reasons.append("Entra idtyp=app (app-only token)")
        elif family == "entra" and ("appid" in claims or "azp" in claims) and not has_user and "oid" in claims:
            identity_type = "service"
            reasons.append("Entra token has appid/azp and oid but no user claims")
        if family == "okta" and claims.get("cid") and claims.get("cid") == sub:
            identity_type = "service"
            reasons.append("Okta cid == sub (service app token)")
        if sub.endswith(".iam.gserviceaccount.com") or str(claims.get("email", "")).endswith(".iam.gserviceaccount.com"):
            identity_type = "service"
            reasons.append("Google service account")
        if family == "cognito" and claims.get("token_use") == "access" and claims.get("client_id") and not claims.get("username"):
            identity_type = "service"
            reasons.append("Cognito client-credentials access token")
        if sub.startswith("spiffe://") or str(claims.get("spiffe_id", "")).startswith("spiffe://"):
            identity_type = "workload"
            reasons.append("SPIFFE workload identity")
            f.add_tag("spiffe")
        if family == "keycloak" and str(sub).startswith("service-account-") or str(claims.get("preferred_username", "")).startswith("service-account-"):
            identity_type = "service"
            reasons.append("Keycloak service account")
        if "act" in claims or "may_act" in claims:
            identity_type = "delegated-agent" if identity_type != "human" else "delegated"
            actor = claims.get("act") or {}
            chain = []
            while isinstance(actor, dict):
                chain.append(str(actor.get("sub") or actor.get("client_id") or "?"))
                actor = actor.get("act")
            reasons.append(f"RFC 8693 actor chain: {' -> '.join(chain) or 'present'}")
            f.add_tag("delegation")
            f.add_capability("delegated-identity")
        azp = claims.get("azp") or claims.get("appid") or claims.get("client_id") or claims.get("cid")
        if azp and aud_list and str(azp) not in aud_list and identity_type == "human":
            reasons.append(f"authorised party {azp} differs from audience (token issued to a client acting for the user)")
        agent_hints = {k: claims[k] for k in AGENT_CLAIM_KEYS if k in claims and k not in {"act", "may_act"}}
        if agent_hints:
            reasons.append(f"agent-related claims: {', '.join(agent_hints)}")
            f.add_tag("agent-claims")
            if identity_type == "human":
                identity_type = "agent"
        hint_text = " ".join(str(v) for v in agent_hints.values()) + " " + " ".join(str(claims.get(k, "")) for k in ("client_name", "app_displayname", "sub", "azp_name"))
        apply_matches(f, name_matches(self.index, hint_text), weight_scale=0.7)
        apply_matches(f, domain_matches(self.index, *aud_list, iss), weight_scale=0.7)

        scopes: list[str] = []
        for key in ("scope", "scp"):
            v = claims.get(key)
            if isinstance(v, str):
                scopes.extend(v.split())
            elif isinstance(v, list):
                scopes.extend(str(x) for x in v)
        for key in ("roles", "permissions", "groups", "wids"):
            v = claims.get(key)
            if isinstance(v, list):
                scopes.extend(str(x) for x in v)
        classify_permissions(self.index, f, scopes)

        iat = parse_timestamp(claims.get("iat"))
        exp = parse_timestamp(claims.get("exp"))
        lifetime_h = (exp - iat).total_seconds() / 3600 if iat and exp else None
        hygiene: list[str] = []
        if not exp:
            hygiene.append("no expiry (exp)")
        elif lifetime_h and lifetime_h > 24:
            hygiene.append(f"long lifetime ({lifetime_h:.0f}h)")
        alg = str(header.get("alg", ""))
        if alg.lower() == "none":
            hygiene.append("alg=none")
        elif alg.upper().startswith("HS") and family in {"okta", "entra", "google", "auth0", "cognito"}:
            hygiene.append(f"symmetric alg {alg} on public issuer")
        if exp and exp < datetime.now(UTC):
            f.add_tag("expired")
        for h in hygiene:
            f.add_tag("token-hygiene")
            f.add_evidence(Evidence(signal="jwt:hygiene", description=h, weight=0.1))

        weight = {"human": 0.05, "delegated": 0.35, "service": 0.5, "workload": 0.5, "agent": 0.6, "delegated-agent": 0.75}[identity_type]
        f.add_evidence(Evidence(signal=f"jwt:{identity_type}", description=f"Identity type '{identity_type}' for sub={sub or '?'} iss={iss or '?'}" + (f" ({'; '.join(reasons)})" if reasons else ""), weight=weight))
        if verified is not None:
            expected_issuer = self.ctx.get("expected_issuer")
            verified_description = (
                "signature and configured issuer verified; expiry and audience NOT validated"
                if expected_issuer else "signature verified against configured JWKS; issuer, expiry and audience NOT validated"
            )
            f.add_evidence(Evidence(signal="jwt:signature", description=verified_description if verified else "signature NOT verified", weight=0.0))
            f.metadata["verified"] = verified
            f.metadata["verification_scope"] = "signature-and-issuer" if expected_issuer else "signature-only"
            f.metadata["issuer_verified"] = bool(verified and expected_issuer)
            f.metadata["authorization_validated"] = False
        f.add_tag(f"identity:{identity_type}")
        f.title = f"JWT ({identity_type}) for {sub or azp or '?'} from {family}"
        f.owner = str(claims.get("email") or claims.get("upn") or claims.get("preferred_username") or "") or None
        f.first_seen = to_iso(iat)
        f.last_seen = to_iso(exp)
        f.metadata.update(
            {
                "issuer": iss,
                "issuer_family": family,
                "subject": sub,
                "audience": aud_list,
                "authorized_party": azp,
                "identity_type": identity_type,
                "reasons": reasons,
                "algorithm": alg,
                "kid": header.get("kid"),
                "lifetime_hours": round(lifetime_h, 1) if lifetime_h else None,
                "scopes": scopes[:40],
                "agent_claims": {k: (v if isinstance(v, (str, int, bool)) else json.dumps(v)[:200]) for k, v in agent_hints.items()},
                "claim_names": sorted(claims.keys()),
                "context": context,
            }
        )
        finalize(f, self.index)
        f.kind = Kind.TOKEN
        f.sanitize()
        return f


def _issuer_family(iss: str, claims: dict[str, Any]) -> str:
    """Describe an issuer namespace, never establish token trust.

    Parse the hostname before matching provider domains: substrings in paths,
    userinfo, query strings or attacker-controlled suffixes prove nothing.
    Generic claims such as ``gty`` are not provider identifiers.
    """
    try:
        parsed = urlsplit(iss)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.username or parsed.password:
            host = ""
    except ValueError:
        return "custom" if iss else "unknown"
    if parsed.scheme not in {"https", "http", "spiffe"}:
        # Google documents this exact scheme-less issuer value.
        host = "accounts.google.com" if iss == "accounts.google.com" else ""

    def domain(name: str) -> bool:
        return host == name or host.endswith("." + name)

    if host in {"login.microsoftonline.com", "sts.windows.net", "login.windows.net", "login.microsoftonline.us", "login.chinacloudapi.cn"}:
        return "entra"
    if any(domain(name) for name in ("okta.com", "oktapreview.com", "okta-emea.com")):
        return "okta"
    if host == "accounts.google.com" or domain("googleapis.com"):
        return "google"
    if domain("auth0.com"):
        return "auth0"
    if re.fullmatch(r"cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?", host):
        return "cognito"
    if host and "/realms/" in parsed.path:
        return "keycloak"
    if parsed.scheme == "spiffe" and host or str(claims.get("sub", "")).startswith("spiffe://"):
        return "spiffe"
    if host == "token.actions.githubusercontent.com":
        return "github-actions"
    if host == "gitlab.com":
        return "gitlab"
    if domain("kubernetes.default.svc") or any(key == "kubernetes.io" or key.startswith("kubernetes.io/") for key in claims):
        return "kubernetes"
    return "custom" if iss else "unknown"
