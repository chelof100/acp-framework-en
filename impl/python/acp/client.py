"""
acp.client — Cliente HTTP ACP con handshake PoP automático (ACP-HP-1.0)

El ACPClient implementa todos los endpoints del protocolo ACP v1:

  ACP-HP-1.0  — Handshake / Proof-of-Possession
    register()           → POST /acp/v1/register         (legacy alias)
    verify()             → POST /acp/v1/verify            (PoP handshake completo)
    health()             → GET  /acp/v1/health

  ACP-CT-1.0  — Capability Tokens
    authorize()          → POST /acp/v1/authorize
    tokens_issue()       → POST /acp/v1/tokens

  ACP-REV-1.0 — Revocation
    revocation_check()   → GET  /acp/v1/rev/check?token_id=
    revoke()             → POST /acp/v1/rev/revoke

  ACP-REP-1.1 — Reputation
    reputation_get()     → GET  /acp/v1/rep/{agent_id}
    reputation_events()  → GET  /acp/v1/rep/{agent_id}/events
    reputation_state()   → POST /acp/v1/rep/{agent_id}/state

  ACP-EXEC-1.0 — Execution Tokens
    exec_token_consume() → POST /acp/v1/exec-tokens/{et_id}/consume
    exec_token_status()  → GET  /acp/v1/exec-tokens/{et_id}/status

  ACP-LEDGER-1.0 — Audit Ledger
    audit_query()        → POST /acp/v1/audit/query
    audit_verify()       → GET  /acp/v1/audit/verify/{event_id}

  ACP-API-1.0 §3 — Agents
    agent_register()     → POST /acp/v1/agents
    agent_get()          → GET  /acp/v1/agents/{agent_id}
    agent_state()        → POST /acp/v1/agents/{agent_id}/state

  ACP-API-1.0 §8 — Escalations
    escalation_resolve() → POST /acp/v1/escalations/{escalation_id}/resolve

Uso:
    from acp.identity import AgentIdentity
    from acp.signer import ACPSigner
    from acp.client import ACPClient

    agent = AgentIdentity.generate()
    signer = ACPSigner(agent)
    client = ACPClient(
        server_url="http://localhost:8080",
        identity=agent,
        signer=signer,
    )

    client.register()
    result = client.verify(capability_token=signed_token)
    result = client.authorize(
        request_id="req-001",
        agent_id=agent.agent_id,
        capability="acp:cap:financial.payment",
        resource="org.example/accounts/ACC-001",
    )
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
import json

from .identity import AgentIdentity
from .signer import ACPSigner


class ACPError(Exception):
    """Lanzado cuando el servidor ACP retorna un error o la solicitud falla."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ─── HTTP helpers (sin dependencias externas) ─────────────────────────────────

def _post_json(url: str, body: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    """POST HTTP con body JSON."""
    data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_bytes = e.read()
        try:
            err = json.loads(body_bytes)
        except Exception:
            err = {"error": body_bytes.decode("utf-8", errors="replace")}
        raise ACPError(
            f"HTTP {e.code}: {err.get('error', str(err))}", status_code=e.code
        ) from e
    except URLError as e:
        raise ACPError(f"Conexión fallida: {e.reason}") from e


def _get_json(url: str, timeout: int = 10) -> Dict[str, Any]:
    """GET HTTP que retorna JSON."""
    req = Request(url)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        raise ACPError(f"HTTP {e.code}", status_code=e.code) from e
    except URLError as e:
        raise ACPError(f"Conexión fallida: {e.reason}") from e


def _get_json_params(url: str, params: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    """GET HTTP con query parameters."""
    if params:
        qs = urlencode({k: v for k, v in params.items() if v is not None})
        full_url = f"{url}?{qs}" if qs else url
    else:
        full_url = url
    return _get_json(full_url, timeout=timeout)


# ─── ACPClient ─────────────────────────────────────────────────────────────────

class ACPClient:
    """
    Cliente HTTP ACP — implementa el handshake Challenge/PoP (ACP-HP-1.0)
    y todos los endpoints de ACP v1.

    Stateless entre llamadas. Cada verify() solicita un nuevo challenge.
    """

    def __init__(
        self,
        server_url: str,
        identity: AgentIdentity,
        signer: ACPSigner,
        timeout: int = 10,
    ) -> None:
        """
        Args:
            server_url: URL base del servidor ACP (ej. "http://localhost:8080").
            identity:   Identidad del agente (par de claves Ed25519).
            signer:     Instancia de ACPSigner para firmas PoP.
            timeout:    Timeout HTTP en segundos.
        """
        self._server = server_url.rstrip("/")
        self._identity = identity
        self._signer = signer
        self._timeout = timeout

    # ─── ACP-HP-1.0: Handshake básico ─────────────────────────────────────────

    def register(self) -> Dict[str, Any]:
        """
        Registra la clave pública del agente con el servidor (legacy alias).

        POST /acp/v1/register
        Body: {"agent_id": "...", "public_key_hex": "<base64url(pubkey)>"}

        Deprecated: usar agent_register() para el endpoint canónico ACP-API-1.0.
        """
        pubkey_b64 = base64.urlsafe_b64encode(
            self._identity.public_key_bytes
        ).rstrip(b"=").decode()
        return _post_json(
            f"{self._server}/acp/v1/register",
            {"agent_id": self._identity.agent_id, "public_key_hex": pubkey_b64},
            timeout=self._timeout,
        )

    def verify(self, capability_token: Dict[str, Any]) -> Dict[str, Any]:
        """
        Flujo completo de verificación ACP (ACP-HP-1.0):
          1. GET /acp/v1/challenge      → nonce de un solo uso
          2. Calcular PoP: Method|Path|Challenge|base64url(SHA-256(body))
          3. POST /acp/v1/verify        → headers Authorization + X-ACP-*

        Args:
            capability_token: Dict de token de capacidad firmado.

        Returns:
            {"ok": true, "agent_id": "...", "capabilities": [...], ...}
        """
        challenge_resp = self._get_challenge()
        challenge = challenge_resp["challenge"]

        token_json = json.dumps(capability_token, separators=(",", ":"))
        body = b""
        pop_sig = self._sign_pop("POST", "/acp/v1/verify", challenge, body)

        return self._post_with_acp_headers(
            f"{self._server}/acp/v1/verify",
            body=body,
            token_json=token_json,
            agent_id=self._identity.agent_id,
            challenge=challenge,
            pop_sig=pop_sig,
        )

    def health(self) -> Dict[str, Any]:
        """GET /acp/v1/health — disponibilidad del servidor."""
        return _get_json(f"{self._server}/acp/v1/health", timeout=self._timeout)

    # ─── ACP-CT-1.0: Capability Tokens ────────────────────────────────────────

    def authorize(
        self,
        request_id: str,
        agent_id: str,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        sig: str = "",
    ) -> Dict[str, Any]:
        """
        Solicita autorización para ejecutar una acción (ACP-CT-1.0).

        POST /acp/v1/authorize

        Si la decisión es APPROVED, la respuesta incluye un execution_token
        listo para ser consumido por el sistema destino (ACP-EXEC-1.0).

        Args:
            request_id:        Identificador único de la solicitud (UUID).
            agent_id:          ID del agente que solicita autorización.
            capability:        Capability requerida (ej. "acp:cap:financial.payment").
            resource:          Recurso objetivo (ej. "org.example/accounts/ACC-001").
            action_parameters: Parámetros adicionales de la acción (opcional).
            context:           Contexto de riesgo adicional (opcional).
            sig:               Firma Ed25519 del agente sobre la solicitud.

        Returns:
            {
                "decision": "APPROVED" | "DENIED" | "ESCALATED",
                "risk_score": <int>,
                "risk_level": "<string>",
                "execution_token": {...}  # solo si APPROVED
            }
        """
        body: Dict[str, Any] = {
            "request_id": request_id,
            "agent_id": agent_id,
            "capability": capability,
            "resource": resource,
            "sig": sig,
        }
        if action_parameters is not None:
            body["action_parameters"] = action_parameters
        if context is not None:
            body["context"] = context
        return _post_json(
            f"{self._server}/acp/v1/authorize",
            body,
            timeout=self._timeout,
        )

    def tokens_issue(
        self,
        issuer_id: str,
        subject_agent_id: str,
        capabilities: List[str],
        resource: str,
        expires_in: int = 3600,
        action_parameters: Optional[Dict[str, Any]] = None,
        sig: str = "",
    ) -> Dict[str, Any]:
        """
        Emite un Capability Token por delegación (ACP-CT-1.0 §4).

        POST /acp/v1/tokens
        Requiere capability: acp:cap:agent.delegate

        Args:
            issuer_id:         ID del agente delegante.
            subject_agent_id:  ID del agente que recibirá el CT.
            capabilities:      Lista de capabilities a delegar.
            resource:          Recurso objetivo del CT.
            expires_in:        Vigencia del token en segundos (default 3600).
            action_parameters: Restricciones de acción opcionales.
            sig:               Firma Ed25519 del emisor sobre la solicitud.

        Returns:
            {
                "token_id":         "...",
                "token_type":       "CAPABILITY",
                "issuer_id":        "...",
                "subject_agent_id": "...",
                "capabilities":     [...],
                "resource":         "...",
                "issued_at":        <unix_ts>,
                "expires_at":       <unix_ts>,
                "sig":              "<base64url>"
            }
        """
        body: Dict[str, Any] = {
            "issuer_id":        issuer_id,
            "subject_agent_id": subject_agent_id,
            "capabilities":     capabilities,
            "resource":         resource,
            "expires_in":       expires_in,
            "sig":              sig,
        }
        if action_parameters is not None:
            body["action_parameters"] = action_parameters
        return _post_json(
            f"{self._server}/acp/v1/tokens",
            body,
            timeout=self._timeout,
        )

    # ─── ACP-REV-1.0: Revocación ──────────────────────────────────────────────

    def revocation_check(self, token_id: str) -> Dict[str, Any]:
        """
        Consulta el estado de revocación de un token (ACP-REV-1.0).

        GET /acp/v1/rev/check?token_id={token_id}

        Returns:
            {"token_id": "...", "status": "active" | "revoked", "checked_at": <unix_ts>}
        """
        return _get_json_params(
            f"{self._server}/acp/v1/rev/check",
            {"token_id": token_id},
            timeout=self._timeout,
        )

    def revoke(
        self,
        token_id: str,
        reason_code: str,
        revoked_by: str,
        revoke_descendants: bool = False,
        sig: str = "",
    ) -> Dict[str, Any]:
        """
        Revoca un token (ACP-REV-1.0 §5). Operación administrativa.

        POST /acp/v1/rev/revoke

        Args:
            token_id:           ID del token a revocar.
            reason_code:        Código de razón (ej. "COMPROMISE", "POLICY_VIOLATION").
            revoked_by:         Identificador del administrador que revoca.
            revoke_descendants: Si True, revoca también tokens derivados.
            sig:                Firma Ed25519 del administrador (opcional en dev).

        Returns:
            {"ok": true, "token_id": "...", "revoked_at": <unix_ts>}
        """
        return _post_json(
            f"{self._server}/acp/v1/rev/revoke",
            {
                "token_id":           token_id,
                "reason_code":        reason_code,
                "revoked_by":         revoked_by,
                "revoke_descendants": revoke_descendants,
                "sig":                sig,
            },
            timeout=self._timeout,
        )

    # ─── ACP-REP-1.1: Reputación ──────────────────────────────────────────────

    def reputation_get(self, agent_id: str) -> Dict[str, Any]:
        """
        Obtiene el registro de reputación de un agente (ACP-REP-1.1).

        GET /acp/v1/rep/{agent_id}

        Returns:
            Registro de reputación con score, state y métricas de comportamiento.
        """
        return _get_json(
            f"{self._server}/acp/v1/rep/{agent_id}",
            timeout=self._timeout,
        )

    def reputation_events(
        self,
        agent_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Obtiene el historial de eventos de reputación de un agente (ACP-REP-1.1).

        GET /acp/v1/rep/{agent_id}/events?limit={limit}&offset={offset}

        Returns:
            {"events": [...], "total": <int>, "limit": <int>, "offset": <int>}
        """
        return _get_json_params(
            f"{self._server}/acp/v1/rep/{agent_id}/events",
            {"limit": limit, "offset": offset},
            timeout=self._timeout,
        )

    def reputation_state(
        self,
        agent_id: str,
        new_state: str,
        reason: str = "",
        authorized_by: str = "",
    ) -> Dict[str, Any]:
        """
        Establece el estado administrativo de reputación de un agente (ACP-REP-1.1 §7).

        POST /acp/v1/rep/{agent_id}/state

        Args:
            agent_id:      ID del agente.
            new_state:     Nuevo estado: "ACTIVE" | "PROBATION" | "SUSPENDED" | "BANNED".
            reason:        Razón del cambio de estado (opcional).
            authorized_by: Identificador del administrador que autoriza (opcional).

        Returns:
            {"ok": true, "agent_id": "...", "state": "..."}
        """
        return _post_json(
            f"{self._server}/acp/v1/rep/{agent_id}/state",
            {
                "new_state":    new_state,
                "reason":       reason,
                "authorized_by": authorized_by,
            },
            timeout=self._timeout,
        )

    # ─── ACP-EXEC-1.0: Execution Tokens ───────────────────────────────────────

    def exec_token_consume(
        self,
        et_id: str,
        consumed_at: int,
        execution_result: str,
        sig: str = "",
    ) -> Dict[str, Any]:
        """
        Reporta el consumo de un Execution Token por el sistema destino (ACP-EXEC-1.0).

        POST /acp/v1/exec-tokens/{et_id}/consume

        Los ET son de un solo uso. El sistema destino confirma la ejecución
        llamando a este endpoint.

        Args:
            et_id:            ID del Execution Token.
            consumed_at:      Timestamp Unix de consumo.
            execution_result: "success" | "failure" | "unknown".
            sig:              Firma Ed25519 del sistema destino (opcional en dev).

        Returns:
            {"et_id": "...", "state": "consumed", "consumed_at": <int>, ...}
        """
        return _post_json(
            f"{self._server}/acp/v1/exec-tokens/{et_id}/consume",
            {
                "et_id":            et_id,
                "consumed_at":      consumed_at,
                "execution_result": execution_result,
                "sig":              sig,
            },
            timeout=self._timeout,
        )

    def exec_token_status(self, et_id: str) -> Dict[str, Any]:
        """
        Consulta el estado actual de un Execution Token (ACP-EXEC-1.0).

        GET /acp/v1/exec-tokens/{et_id}/status

        Returns:
            {
                "et_id": "...", "authorization_id": "...", "agent_id": "...",
                "capability": "...", "resource": "...",
                "issued_at": <unix_ts>, "expires_at": <unix_ts>,
                "state": "active" | "consumed" | "expired"
            }
        """
        return _get_json(
            f"{self._server}/acp/v1/exec-tokens/{et_id}/status",
            timeout=self._timeout,
        )

    # ─── ACP-LEDGER-1.0: Audit Ledger ─────────────────────────────────────────

    def audit_query(
        self,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        time_range_from: Optional[int] = None,
        time_range_to: Optional[int] = None,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Consulta el audit ledger hash-chained con filtros (ACP-LEDGER-1.0 §6).

        POST /acp/v1/audit/query

        Args:
            event_type:      Filtrar por tipo de evento (ej. "AUTHORIZATION").
            agent_id:        Filtrar por agent_id en el payload del evento.
            time_range_from: Timestamp Unix inicio del rango de tiempo (inclusivo).
            time_range_to:   Timestamp Unix fin del rango de tiempo (inclusivo).
            from_sequence:   Secuencia inicial (inclusiva). None = desde inicio.
            to_sequence:     Secuencia final (inclusiva). None = hasta el último.
            limit:           Máximo de eventos a retornar. None = sin límite.
            offset:          Desplazamiento para paginación. None = desde 0.

        Returns:
            {"events": [...], "count": <int>, "total": <int>, "chain_valid": true|false}
        """
        body: Dict[str, Any] = {}
        if event_type is not None:
            body["event_type"] = event_type
        if agent_id is not None:
            body["agent_id"] = agent_id
        if time_range_from is not None or time_range_to is not None:
            body["time_range"] = {}
            if time_range_from is not None:
                body["time_range"]["from"] = time_range_from
            if time_range_to is not None:
                body["time_range"]["to"] = time_range_to
        if from_sequence is not None:
            body["from_sequence"] = from_sequence
        if to_sequence is not None:
            body["to_sequence"] = to_sequence
        if limit is not None:
            body["limit"] = limit
        if offset is not None:
            body["offset"] = offset
        return _post_json(
            f"{self._server}/acp/v1/audit/query",
            body,
            timeout=self._timeout,
        )

    def audit_verify(self, event_id: str) -> Dict[str, Any]:
        """
        Verifica la integridad de un evento específico (ACP-LEDGER-1.0).

        GET /acp/v1/audit/verify/{event_id}

        Returns:
            {"event": {...}, "chain_valid": true|false, "errors": [...]}
        """
        return _get_json(
            f"{self._server}/acp/v1/audit/verify/{event_id}",
            timeout=self._timeout,
        )

    # ─── ACP-API-1.0 §3: Agents ───────────────────────────────────────────────

    def agent_register(
        self,
        agent_id: str,
        public_key_b64: str,
        autonomy_level: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Registra un nuevo agente en el sistema (ACP-API-1.0 §3).

        POST /acp/v1/agents

        Args:
            agent_id:       Identificador único del agente.
            public_key_b64: Clave pública Ed25519 en base64url (sin padding).
            autonomy_level: Nivel de autonomía 0-3 (default 1).
            metadata:       Metadatos adicionales del agente (opcional).

        Returns:
            {"agent_id": "...", "status": "active", "autonomy_level": <int>, ...}
        """
        body: Dict[str, Any] = {
            "agent_id":       agent_id,
            "public_key_hex": public_key_b64,
            "autonomy_level": autonomy_level,
        }
        if metadata is not None:
            body["metadata"] = metadata
        return _post_json(
            f"{self._server}/acp/v1/agents",
            body,
            timeout=self._timeout,
        )

    def agent_get(self, agent_id: str) -> Dict[str, Any]:
        """
        Obtiene los datos de un agente registrado (ACP-API-1.0 §3).

        GET /acp/v1/agents/{agent_id}

        Returns:
            {
                "agent_id": "...", "status": "active"|"suspended"|"revoked",
                "autonomy_level": <int>, "registered_at": <unix_ts>,
                "last_active": <unix_ts>, ...
            }
        """
        return _get_json(
            f"{self._server}/acp/v1/agents/{agent_id}",
            timeout=self._timeout,
        )

    def agent_state(
        self,
        agent_id: str,
        new_state: str,
        reason: str = "",
        authorized_by: str = "",
    ) -> Dict[str, Any]:
        """
        Cambia el estado administrativo de un agente (ACP-API-1.0 §3).

        POST /acp/v1/agents/{agent_id}/state

        Args:
            agent_id:      ID del agente.
            new_state:     Nuevo estado: "active" | "suspended" | "revoked".
            reason:        Razón del cambio (opcional).
            authorized_by: Administrador que autoriza el cambio (opcional).

        Returns:
            {"agent_id": "...", "state": "..."}
        """
        return _post_json(
            f"{self._server}/acp/v1/agents/{agent_id}/state",
            {
                "new_state":    new_state,
                "reason":       reason,
                "authorized_by": authorized_by,
            },
            timeout=self._timeout,
        )

    # ─── ACP-API-1.0 §8: Escalations ──────────────────────────────────────────

    def escalation_resolve(
        self,
        escalation_id: str,
        resolution: str,
        resolved_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Resuelve una escalación pendiente de revisión humana (ACP-API-1.0 §8).

        POST /acp/v1/escalations/{escalation_id}/resolve

        Args:
            escalation_id: ID de la escalación a resolver.
            resolution:    Decisión: "APPROVED" | "DENIED".
            resolved_by:   Identificador del revisor humano.
            notes:         Notas o justificación de la decisión (opcional).

        Returns:
            {"escalation_id": "...", "resolution": "...", "resolved_at": <unix_ts>}
        """
        return _post_json(
            f"{self._server}/acp/v1/escalations/{escalation_id}/resolve",
            {
                "resolution":  resolution,
                "resolved_by": resolved_by,
                "notes":       notes,
            },
            timeout=self._timeout,
        )

    # ─── Interno ──────────────────────────────────────────────────────────────

    def _get_challenge(self) -> Dict[str, Any]:
        """Obtiene un nonce de 128 bits de un solo uso (ACP-HP-1.0 §2)."""
        return _get_json(f"{self._server}/acp/v1/challenge", timeout=self._timeout)

    def _sign_pop(self, method: str, path: str, challenge: str, body: bytes) -> str:
        """
        Calcula la firma Proof-of-Possession (ACP-HP-1.0 channel binding).

        signed_payload = Method|Path|Challenge|base64url(SHA-256(body))
        sig = Ed25519(sk, SHA-256(signed_payload_bytes))

        Retorna firma en base64url sin padding.
        """
        body_hash = hashlib.sha256(body).digest()
        body_hash_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode()
        signed_payload = f"{method}|{path}|{challenge}|{body_hash_b64}"
        payload_hash = hashlib.sha256(signed_payload.encode("utf-8")).digest()
        sig_bytes = self._signer.sign_bytes(payload_hash)
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    def _post_with_acp_headers(
        self,
        url: str,
        body: bytes,
        token_json: str,
        agent_id: str,
        challenge: str,
        pop_sig: str,
    ) -> Dict[str, Any]:
        """POST con headers de autenticación ACP (ACP-HP-1.0 §3)."""
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token_json}",
            "X-ACP-Agent-ID": agent_id,
            "X-ACP-Challenge": challenge,
            "X-ACP-Signature": pop_sig,
        }
        req = Request(url, data=body, headers=headers)
        try:
            with urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            body_bytes = e.read()
            try:
                err = json.loads(body_bytes)
            except Exception:
                err = {"error": body_bytes.decode("utf-8", errors="replace")}
            raise ACPError(
                f"HTTP {e.code}: {err.get('error', str(err))}", status_code=e.code
            ) from e
        except URLError as e:
            raise ACPError(f"Conexión fallida: {e.reason}") from e
