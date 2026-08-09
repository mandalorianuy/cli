# T7 — Security Intelligence Context Correlation Expansion

Base exacta: T6 `6c68b1bd460d1e9a51f973971bbd9811c494eafd`.

## Plan activo

Agregar una vertical local para contextualizar un reporte ya observado, sin
recolectar evidencia viva ni cambiar el contrato existente del observer o de
`security_intelligence_monitor_v1`.

1. Leer sólo un reporte JSON local bounded y exigir `mode=read-only`, las cinco
   fuentes Google (`login`, `admin`, `token`, `drive`, `rules`) y una ventana
   temporal válida.
2. Normalizar únicamente actor/email, `resourceId`, cliente OAuth, target y
   regla desde campos allowlisted; rechazar identificadores ambiguos, claves de
   evidencia desconocidas, valores inseguros, duplicados conflictivos y
   entradas fuera de límites.
3. Correlacionar por coincidencia exacta y ventana bounded. Emitir un contrato
   independiente `security_intelligence_monitor_correlation_v1` con UUIDv5,
   SHA-256, `quickView` de hasta 300 caracteres y campos humanos vacíos.
4. Incorporar postura/cross-cloud sólo cuando ya esté en el reporte local;
   `disabled`, `unavailable`, stale, incomplete, contradiction y overflow
   conservan `failClosed=true` y aserciones `HECHO`, `INFERENCIA` y
   `DATO FALTANTE`; identificadores ambiguos y evidencia insegura se rechazan
   fail-closed.
5. Mantener IP intelligence como contexto observado únicamente; nunca como
   prueba de seguridad, identidad, autorización o ausencia de compromiso.

## Criterios de aceptación

- El helper es opt-in, requiere `--dry-run`, no usa credenciales, scopes,
  red, APIs externas, writers, notifiers, Sheets, Gmail, migraciones, cutover
  ni remediation.
- El límite de entrada es 1 MiB, el de señales es 1.000, cada correlación es
  de hasta 32 señales y la salida es de hasta 100 correlaciones.
- Hay pruebas para correlación positiva, contexto benigno sin declarar
  limpieza, contradicción, datos faltantes, privacidad/allowlist, IDs y
  fingerprint deterministas, ventana temporal, IP contextual y overflow.
- Se preservan los outputs existentes y se agrega el changeset de la nueva
  capacidad.
- La validación técnica requerida queda separada de aprobación humana,
  autorización de evidencia viva, producción y efecto externo.
