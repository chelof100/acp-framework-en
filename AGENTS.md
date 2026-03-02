# AGENTS.md — ACP Project Workflow Rules

Patterns, gotchas and mandatory workflow rules for AI agents working on this project.

---

## 🔴 REGLA OBLIGATORIA — Al completar cualquier tarea

Cada tarea terminada SIEMPRE debe hacer los tres pasos:

### 1. Push repo EN
```bash
cd ACP-PROTOCOL-EN
git add <archivos>
git commit -m "tipo(scope): descripción"
git push
```

### 2. Push repo ES (mirror)
```bash
cd ACP-PROTOCOL
# copiar los mismos archivos modificados
git add <archivos>
git commit -m "tipo(scope): descripción en español"
git push
```

### 3. Actualizar Obsidian
Vault: `C:\Users\Mariana\Desktop\Chelo\traslaia-brain\proyectos\ACP - Agent Control Protocol\`

Notas disponibles:
- `🏠 Home.md` — hub principal
- `Visión y Arquitectura.md` — arquitectura y decisiones
- `Especificaciones ACP.md` — specs con estado
- `Criptografía ACP.md` — primitivas crypto
- `Go Server — Implementación Referencia.md` — Go server
- `Python SDK.md` — Python SDK
- `Testing y Compliance.md` — test vectors, runner
- `Roadmap ACP.md` — versiones y commits clave

Actualizar la nota relevante con lo que cambió. Si es algo mayor, también actualizar `Roadmap ACP.md` con el commit hash.

---

## Rutas de repos

| Repo | Path local | GitHub |
|---|---|---|
| EN (primario) | `C:/Users/Mariana/Desktop/Chelo/ACP/ACP-PROTOCOL-EN` | chelof100/acp-framework-en |
| ES (mirror) | `C:/Users/Mariana/Desktop/Chelo/ACP/ACP-PROTOCOL` | chelof100/acp-framework |

---

## Gotchas conocidos

### Token fields — exacto match con Go struct
El struct `CapabilityToken` en Go define exactamente: `ver, iss, sub, cap, resource, iat, exp, nonce, sig`.
Campos extra (`jti`, `constraints`, `capabilities`) rompen la verificación JCS. **No agregar campos extra.**

### AgentID — base58(SHA-256(raw_pubkey))
Sin prefijo `acp:agent:`. Sin base64url. Solo base58 Bitcoin alphabet (43-44 chars).

### Signature field — plano, no anidado
`token["sig"]` = base64url(firma). **NO** `token["proof"]["signature"]`.

### PoP binding
`Method|Path|Challenge|base64url(SHA-256(body))` → SHA-256 → Ed25519.
El body para `/acp/v1/verify` es vacío (`b""`), pero el hash se incluye igual.

### Register antes de Verify
El Go server requiere `POST /acp/v1/register` con `{agent_id, public_key_hex}` antes de poder hacer `/acp/v1/verify`.

### Puerto configurable
`ACP_ADDR=":8081"` si 8080 está ocupado.

### institution seed determinístico para tests
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55` (RFC 8037 key A)
→ pubkey: `cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE`
