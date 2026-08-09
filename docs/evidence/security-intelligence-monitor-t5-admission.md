# T5 — Admisión técnica y dossier de decisión humana

**Artefacto:** `security_intelligence_monitor_t5_admission_v1`
**Veredicto T5:** `PASS` técnico; la autoridad operativa, humana y viva sigue `PENDING`.
**Efecto externo:** ninguno.
**Writer externo:** no implementado ni admitido.

## Plan y parentesco exacto

Plan activo: inteligencia multicloud read-only y cutover gobernado.

| Componente | SHA exacto | Estado al cierre de T5 |
| --- | --- | --- |
| T1 postura Google Workspace + Microsoft 365 read-only | `a4d7db1bd243a519dc21dc885e905bb8ba65b03c` | aceptación técnica registrada previamente |
| T2 contrato `security_intelligence_monitor_v1` | `aa0e46e8c4e90ab2f72e6fc5b08c06bbc574f98d` | aceptación técnica registrada previamente |
| T3 planificador local/fail-closed | `8302f265d10896a0e038986b20919609c52fc0b3` | auditado |
| T3b cutover bundle schema 7 | `e550baeaa08a16667de7c3773923d32986a25380` | auditado |
| T4 compilador/simulador transaccional local | `fe259345cc0c13228907c03fe2d58250c3097e1e` | auditado |

La auditoría comenzó en `fe259345cc0c13228907c03fe2d58250c3097e1e`, cuyo padre
exacto es `e550baeaa08a16667de7c3773923d32986a25380`; el merge-base con T2 es
`aa0e46e8c4e90ab2f72e6fc5b08c06bbc574f98d`. El SHA final de T5 debe ser el
único commit local sobre ese head y se verifica con:

```bash
git rev-parse HEAD
git rev-parse HEAD^
git merge-base aa0e46e8c4e90ab2f72e6fc5b08c06bbc574f98d HEAD
git status --short --branch
```

## Decisión registrada

| Gate | Estado | Alcance |
| --- | --- | --- |
| Admisión técnica T3/T3b/T4 | `ACCEPTED` por este dossier | determinismo, invariantes, rechazo adversarial y simulación local |
| Schema 7 aprobado | `PENDING` | no es inferible de una simulación |
| Identidad real tenant/spreadsheet | `PENDING` | sólo se exige y valida en el artefacto local |
| Backup real y restore comprobado | `PENDING` | no se llamó Sheets ni se mutó un target |
| Readback real | `PENDING` | las assertions son locales, no evidencia de servicio |
| Política To/Bcc aprobada | `PENDING` | la policy local no es autorización humana |
| Autoridad de writer/notifier | `PENDING` | no existe ruta de apply en T5 |
| Aceptación operativa/humana | `PENDING` | no se ejecutó |
| Cutover, email, producción | `NOT_AUTHORIZED` / `NOT_DONE` | no ocurrieron |

## Cambios acotados realizados

- T3b ahora calcula capacidad sobre la unión normalizada target+input, rechaza
  capacidad cero, fórmulas en `actor` y guards de snapshot duplicados que
  discrepan.
- T4 ahora exige la cadena tipada completa T3b: versiones/contrato, gate,
  preconditions de IDs y capacidad, migración schema 7 completa, proyección
  top-level coherente con las tres hojas y manifests de notificación idénticos.
- T4 exige identidad explícita `tenantId`/`spreadsheetId`, pin de
  `revision` o `etag` en todas las fases y readback, el conjunto completo de
  campos humanos, UUIDs con prefijo por colección, y correspondencia exacta
  key/record/action.
- La verificación de receipts ya no confía sólo en hashes: reconstruye cadena
  de estados, transiciones, resultado de readback, rollback, estado final e
  invariantes.
- `+security-monitor-plan` y `+security-monitor-program` usan un command tree
  sintético local antes de Discovery; requieren `--dry-run`/`--simulate` y
  sólo leen JSON local.
- Se actualizó la documentación de T4 y se añadió este dossier junto con el
  changeset requerido.

No se implementó adapter writer, mutación Sheets, migración viva, envío Gmail,
readback externo, restore, credenciales, tokens ni cambios de políticas.

## Matriz de invariantes

| Invariante auditado | Resultado | Evidencia |
| --- | --- | --- |
| No-effect real y ausencia de apply oculto | `PASS` técnico | flags fijos, handlers locales, dispatch sintético, tests CLI negativos |
| Fingerprints canónicos y determinismo | `PASS` técnico | tests de orden/canonicalización y compilación estable |
| Idempotencia y replay | `PASS` técnico | replay exacto devuelve `noop`; divergencia/replay incompleto rechaza |
| Orden estricto de fases | `PASS` técnico | nueve fases tipadas, secuencia y dependencia previa verificadas |
| Receipts, rollback y notification suppression | `PASS` técnico | fallos de cada fase, rollback failure, cadena de estados/transiciones |
| Preservación de campos humanos | `PASS` mecánico | patch humano rechazado, lista completa y assertions exactas |
| Política To/Bcc exacta y hasheada | `PASS` mecánico | policy fixed, roles no vacíos/duplicados/placeholder, fingerprint de policy |
| IDs, URLs, fórmulas, ranges, keys y límites | `PASS` técnico | validadores y casos negativos de inyección, UUID, capacity y overlap |
| Compatibilidad T3 → T3b → T4 | `PASS` estructural | metadata, preconditions, schema additions, plan/hojas y readback alineados |
| Identidad/pin de target | `PASS` de admisión local | tenant/spreadsheet obligatorios y revision o etag propagados |
| Schema 6 | `PASS` fail-closed | permanece bloqueado; no se declara schema 7 aprobado |
| Backup/restore, readback y tenant reales | `PENDING` | requieren evidencia externa y decisión humana |

## Falsaciones ejecutadas

La suite focal incluye y pasa casos para:

- overflow de capacidad con claves disjuntas target/input;
- `actor` formula-like, valores fórmula/URL no allowlisted y campos inseguros;
- claves no UUID, key/record discrepantes, acciones/eligibility inconsistentes,
  duplicados y rangos superpuestos;
- guards anidados/top-level contradictorios y target sólo con `etag`;
- identidad tenant/spreadsheet ausente o divergente;
- human patch, human-field set incompleto, migración/additions incompletas y
  plan top-level divergente de las hojas;
- receipts re-hasheados con estados/transiciones falsos y assertions de
  readback modificadas;
- orden/fallo de cada fase, rollback fallido y replay no exacto.

Las negativas CLI ejecutadas sin credenciales ni APIs externas fueron:

```bash
./target/debug/gws admin-reports +security-monitor-plan \
  --input evidence/does-not-exist.json \
  --existing evidence/does-not-exist-target.json
# exit 3: requires --dry-run; external cutover is not implemented

./target/debug/gws admin-reports +security-monitor-program \
  --bundle evidence/does-not-exist.json \
  --target evidence/does-not-exist-target.json \
  --policy evidence/does-not-exist-policy.json
# exit 3: --simulate is required
```

Con `--dry-run`/`--simulate`, los mismos comandos fallaron al leer el archivo
local inexistente, antes de cualquier operación externa. El código de Discovery
queda sólo en la rama que no coincide con esos helpers locales.

## Validación reproducible

| Comando | Resultado |
| --- | --- |
| `cargo fmt --all -- --check` | `PASS` |
| `cargo test -p google-workspace-cli monitor -- --nocapture` | `PASS`, 47 tests |
| `cargo test` | `PASS`, 82 library tests + 794 CLI tests + 0 doctests |
| `cargo build -p google-workspace-cli` | `PASS` |
| `cargo clippy -p google-workspace-cli --bin gws -- -D warnings` | `PASS` |
| `cargo clippy --all-targets --all-features -- -D warnings` | sólo los 10 lints preexistentes gobernados abajo |
| `git diff --check` | `PASS` |

El clippy all-targets conserva exactamente estos diez bloqueos preexistentes,
fuera de T5 y sin lint nuevo en los cambios de esta task: `credential_store.rs`
`type_complexity`; `executor.rs` `bool_assert_comparison` y
`unnecessary_literal_unwrap`; `helpers/chat.rs`, `helpers/docs.rs` y
`helpers/sheets.rs` `field_reassign_with_default`; `helpers/gmail/reply.rs`
`needless_borrows_for_generic_args`; `setup.rs` `manual_contains`; y dos
`bool_assert_comparison` preexistentes en `main.rs`. Se aíslan como deuda
preexistente, no como evidencia de PASS de ese comando completo.

## Ledger residual

- **R-T5-01 — autoridad humana:** schema 7, writer, notifier, To/Bcc,
  aceptación operativa y cutover siguen pendientes.
- **R-T5-02 — evidencia viva:** falta snapshot real, backup/restore probado,
  identidad real tenant/spreadsheet y readback contra el servicio.
- **R-T5-03 — custodia de artefactos:** SHA-256 es fingerprint de integridad,
  no firma ni prueba por sí solo quién autorizó el bundle/policy. La custodia y
  reconciliación humana deben ser independientes.
- **R-T5-04 — cobertura:** T5 valida flags y estructura local; no convierte
  fixtures ni cobertura observada en prueba de disponibilidad actual de Google,
  Microsoft, Sheets o Gmail.
- **R-T5-05 — clippy heredado:** permanecen los diez lints enumerados hasta que
  una task separada los gobierne sin mezclarlos con T5.

## Siguiente task gobernada

La siguiente task es exclusivamente **decisión humana/operativa sobre este
dossier**: revisar los fingerprints, target/policy, schema 7, backup/restore,
To/Bcc y autoridad. Si la decisión no es positiva, debe abrirse una corrección
exacta del gate correspondiente. No habilita por sí misma un writer ni un
cutover; cualquier adapter writer futuro requiere una autorización separada.
