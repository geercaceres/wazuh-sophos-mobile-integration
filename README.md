# Integración Sophos Mobile → Wazuh (vía API)

Sophos Mobile SaaS **no soporta syslog**. Esta integración usa la API de Sophos
Central y emite JSON lines que Wazuh ingiere con `log_format json`.

| Fuente | `sophos_record` |
| --- | --- |
| `siem/v1/events` | `event` |
| `siem/v1/alerts` | `alert` |
| `mobile/v1/devices` | `device_status` |
| `mobile/v1/devices/{id}/compliance-violations` | `compliance_violation` |
| `mobile/v1/devices/{id}/installed-apps` | `installed_app`, `app_removed`, `forbidden_app` |

> **Estado: desplegado y verificado en vivo** contra el tenant del trial (región
> `us03`) sobre Wazuh 4.14.7, con el Dell Inspiron enrolado. 42 reglas, suite de
> 44 tests en `wazuh-logtest` pasando, y dashboard cargado.

## Hallazgos de la API real (correcciones a la investigación inicial)

| Asunción inicial | Realidad verificada |
| --- | --- |
| `/smc/v1/devices` | **404** `ApplicationNotFound`. En tenants gestionados por Central el path es **`/mobile/v1/devices`** |
| `sophos.complianceStatus` con valores `non*`/`violat*` | `compliance.compliant`, booleano |
| `sophos.managementStatus` | `managedState`, con valor `"managed"` |
| `sophos.type` contiene `compliance` | `Event::Endpoint::Mobile::NowCompliant`, `::Added`, `::Enrolled`, `::Action::Succeeded` |
| `limit` libre en SIEM API | Obligatorio **200 ≤ limit ≤ 1000** (fuera de rango → HTTP 400) |

Endpoints que existen y devuelven 200: `mobile/v1/devices`, `.../compliance-violations`,
`.../installed-apps`, `mobile/v1/policies`.
No existen (404): `mobile/v1/apps`, `mobile/v1/tasks`, `.../certificates`, todo `smc/v1/*`.

### Payload real de `mobile/v1/devices`

```json
{
  "id": "<device-uuid>", "name": "test-device-01",
  "compliance": {"compliant": true},
  "healthState": {"mode": "automatic", "state": "green"},
  "managedState": "managed", "managementType": "fullMdm",
  "os": {"platform": "windows", "name": "Windows 10.0.26200.8973"},
  "ownershipType": "corporate", "lastSeenAt": "2026-08-03T11:44:03.000Z",
  "email": "...", "tenant": {"id": "<tenant-uuid>"}
}
```

### Payload real de `siem/v1/events`

```json
{
  "endpoint_type": "mobile", "endpoint_id": "<device-uuid>",
  "severity": "low", "group": "MOBILES",
  "type": "Event::Endpoint::Mobile::NowCompliant",
  "name": "The mobile device is now compliant",
  "location": "test-device-01", "source": "user name",
  "when": "...", "created_at": "...", "id": "...",
  "customer_id": "...", "user_id": "...", "source_info": {}
}
```

## Instalación

**1. Crear las credenciales en Sophos Central**

Global Settings → API Credentials Management → Add Credential, rol
**Service Principal ReadOnly**. El client secret se muestra una sola vez.

**2. Configurarlas localmente** (`credentials.env` está en `.gitignore`, nunca
se commitea):

```bash
cp credentials.env.example credentials.env
$EDITOR credentials.env
```

**3. Desplegar:**

```bash
bash deploy.sh wazuh-user@wazuh-manager.example.com
```

`deploy.sh` genera el archivo de config, lo copia por `scp` (nunca como argumento
de línea de comandos) y ejecuta `setup-remote.sh` como root, que instala script +
reglas + credenciales, parchea `ossec.conf`, **valida con `wazuh-analysisd -t`
antes de reiniciar** e imprime un test de auth/fetch.

### Dashboard

```bash
scp dashboard/sophos-mobile-dashboard.ndjson dashboard/load-dashboard.sh wazuh-user@HOST:/tmp/
ssh wazuh-user@HOST 'sudo bash /tmp/load-dashboard.sh /tmp/sophos-mobile-dashboard.ndjson'
```

Para regenerar los saved objects (por ejemplo con otro index pattern):

```bash
python3 dashboard/make_dashboard.py out.ndjson [index-pattern-id] [field-suffix]
```

### Probar las reglas

```bash
scp tests/rule-tests.sh wazuh-user@HOST:/tmp/
ssh wazuh-user@HOST 'sudo bash /tmp/rule-tests.sh'
```

44 casos contra `wazuh-logtest`, incluidos escenarios de Android que un tenant
sin dispositivos Android no puede generar (root, malware, PUA, ADB, apps
prohibidas).

12 paneles + 1 saved search, en inglés:
métricas (total, violaciones de compliance, amenazas móviles, nivel ≥ 10),
serie temporal por nivel, torta por tipo de registro, torta por plataforma,
tablas de reglas / dispositivos / eventos / inventario de apps, y las últimas
alertas. Referencia el index pattern `wazuh-alerts-*` sin modificarlo.

```
https://wazuh-manager.example.com/app/dashboards#/view/sophos-mobile-dashboard
```

## Configuración

Lo que escribís en `credentials.env` termina en
`/var/ossec/etc/sophos-mobile.json` (root:wazuh, 0640):

```json
{
  "client_id": "...",
  "client_secret": "...",
  "poll_installed_apps": true,
  "forbidden_apps": ["(?i)tiktok", "(?i)telegram"]
}
```

`forbidden_apps` son regex de Python evaluadas contra el identifier y el nombre
de cada app instalada. Cada coincidencia dispara la regla **100628 (nivel 12)**,
una vez por dispositivo y app; si se desinstala y se reinstala, vuelve a alertar.
Esto cubre el caso de "apps prohibidas" **sin depender de que el cliente
configure compliance policies en Sophos**.

## Verificación

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-sophos-mobile.py --test
tail -f /var/ossec/logs/alerts/alerts.json | grep sophos_mobile
```

Para probar reglas sin esperar eventos reales — un registro por línea, y
**sin `-q`**, que suprime toda la salida:

```bash
echo '{"integration":"sophos_mobile","sophos_record":"device_status","sophos":{"name":"dev1","compliance":{"compliant":false},"managedState":"managed"}}' | /var/ossec/bin/wazuh-logtest
```

## Estructura del evento en Wazuh

```json
{
  "integration": "sophos_mobile",
  "sophos_record": "event | alert | device_status | compliance_violation | installed_app | app_removed | forbidden_app",
  "sophos": { "...payload de Sophos + campos que agrega la integración..." }
}
```

El decoder JSON nativo de Wazuh lo decodifica solo, sin decoder custom. Dos
detalles que importan para escribir reglas:

- Los objetos anidados se aplanan con puntos (`sophos.compliance.compliant`).
- **Los booleanos llegan como string**, por eso la regla de compliance matchea
  `"false"` y no `false`.

Todos los campos quedan mapeados como `keyword` en el indexer, así que son
agregables sin sufijo `.keyword`.

## Reglas (100600-100649)

**El orden en el archivo importa**: Wazuh evalúa las reglas hermanas en orden y
se queda con la **primera** que matchea, no con la más específica ni la de mayor
nivel. Por eso las reglas por severidad (100602/100603) están deliberadamente
**al final** de las hijas de 100601. Si agregás reglas nuevas, ponelas antes.

### Base y catch-all

| ID | Nivel | Dispara con |
| --- | --- | --- |
| **100600** | 3 | **Catch-all: cualquier registro de la integración.** Nada de Sophos se descarta en silencio: lo que no matchee ninguna regla hija alerta acá |
| 100601 | 3 | `sophos_record=event` sin clasificar |

Para ver *todo* en el dashboard: `rule.groups:sophos_mobile`.

### Eventos SIEM

| ID | Nivel | Dispara con |
| --- | --- | --- |
| 100648 | 12 | Root / jailbreak en el texto del evento |
| 100641 | 12 | `type` = `Threat::(Detected\|CleanupFailed)` |
| 100642 | 12 | malware / malicious app / trojan en el texto |
| 100643 | 10 | `type` = `Threat::Pua*` |
| 100649 | 10 | suspicious app / PUA(s) en el texto |
| 100644 | 9 | `type` = `Application::(Blocked\|Detected)` |
| 100645 | 7 | `WebControlViolation`, `WebFilteringBlocked` |
| 100610 | 3 | `NowCompliant` / `Endpoint::Compliant` (volvió a compliance) |
| 100611 | 9 | `type` contiene `(Not\|Non\|In)Compliant` |
| 100612 | 9 | Fallback por texto: `not/non compliant` |
| 100636 | 9 | ADB / developer mode / USB debugging |
| 100637 | 9 | Encryption |
| 100638 | 9 | Forbidden / mandatory / installed apps, unknown sources, third-party profiles |
| 100639 | 7 | Screen lock / passcode |
| 100613 | 3 | `type` = `Mobile::(Added\|Enrolled)` |
| 100614 | 7 | `type` = `Mobile::(Removed\|Deleted\|Unenrolled\|Deregistered)` |
| 100615 | 7 | `type` = `Mobile::Action::Failed` |
| 100646 | 7 | `Management::Suspended` |
| 100647 | 5 | `OutOfDate` / `UpdateFailure` |
| 100602 | 7 | *Fallback*: `severity=medium` |
| 100603 | 12 | *Fallback*: `severity=high\|critical` |

### Alertas SIEM

| ID | Nivel | Dispara con |
| --- | --- | --- |
| 100619 | 12 | Descripción con root / jailbreak / malware |
| 100618 | 12 | `severity=high\|critical` |
| 100617 | 7 | Cualquier otra alerta |

### Inventario de dispositivos

| ID | Nivel | Dispara con |
| --- | --- | --- |
| 100620 | 3 | `device_status` (cambio de inventario) |
| **100621** | 9 | **`compliance.compliant` = `false` → NO COMPLIANT** |
| **100622** | 7 | **`managedState` ≠ `managed` (`negate="yes"`) → salió de MDM** |
| 100623 | 10 | `healthState.state` = `red` |
| 100624 | 7 | `healthState.state` = `suspicious` |

### Violaciones de compliance e inventario de apps

| ID | Nivel | Dispara con |
| --- | --- | --- |
| 100625 | 9 | `compliance_violation` sin clasificar |
| 100630 | 12 | Root / jailbreak |
| 100631 | 12 | Malware |
| 100632 | 10 | Suspicious / PUA(s) |
| 100633 | 9 | ADB / developer mode |
| 100634 | 9 | Encryption |
| 100635 | 9 | Mandatory / forbidden / installed apps, unknown sources |
| 100640 | 7 | Screen lock, versión de OS, permisos, intervalos de sync, roaming, container, web filtering |
| 100626 | 3 | `installed_app` (app nueva) |
| 100627 | 3 | `app_removed` |
| **100628** | 12 | **`forbidden_app` (match de `forbidden_apps`)** |

Grupos útiles para filtrar: `sophos_mobile`, `compliance_violation`,
`mobile_threat`, `mobile_app_inventory`.

## Cobertura Android / iOS: qué está verificado y qué no

**Verificado con datos reales:** todo lo de `device_status`, los 5 tipos de
evento que produjo el tenant, el polling de `installed-apps` (195 apps en el
Dell) y el camino completo de `forbidden_app` → alerta 100628.

**No verificado, matcheado por texto:** los identificadores
`Event::Endpoint::Mobile::*` no están documentados públicamente y este tenant
solo generó cinco. Las reglas de Android/iOS por lo tanto **no adivinan strings
de `type`**: matchean los *nombres de las reglas de compliance* de la doc
oficial de Sophos, que aparecen en el texto del evento y en el payload de la
violación:

- Android: `Root access allowed`, `Android Debug Bridge (ADB) allowed`,
  `Malware apps allowed`, `Suspicious apps allowed`, `PUAs allowed`,
  `Encryption required`, `Screen lock required`, `Minimum/Maximum OS version`,
  `Mandatory apps`, `Installed apps`, `Intercept X for Mobile permissions can be denied`
- iOS: `Allow jailbreak`, `Third-party profiles allowed`,
  `Unmanaged apps from unknown sources allowed`, `Web Filtering turned on`

([Available compliance rules](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/CompliancePolicies/AvailableComplianceRules/))

El payload de `compliance-violations` sigue siendo desconocido (el tenant no
tiene violaciones activas), así que la integración emite además
**`sophos.violationText`** — la violación entera serializada a un string — y las
reglas 1006[3x] matchean sobre eso en lugar de sobre claves inventadas. Cuando
llegue un payload real, conviene apretarlas a las claves verdaderas.

## Notas operativas

- **Primer lote:** cuando logcollector descubre un archivo monitoreado que *ya*
  tiene contenido, salta al final y nunca lee lo previo. `setup-remote.sh` crea
  `events.json` vacío antes del restart para evitarlo. Si te quedaste sin las
  alertas iniciales: `rm -f /var/ossec/var/sophos-mobile.state` y volvé a correr
  el script.
- **Baseline de apps:** la primera vez que se ve un dispositivo, su lista de apps
  se guarda *sin alertar* (si no, entrarían 195 alertas de una). Desde ahí solo
  se reportan altas y bajas. El chequeo de `forbidden_apps` sí corre en esa
  primera pasada, porque una app prohibida ya instalada es justo lo que hay que
  reportar.
- **Costo por ciclo:** cada corrida hace 2 llamadas SIEM + 1 de devices + 2 por
  dispositivo (violations + apps). Con muchos dispositivos, subí el `<interval>`
  o poné `poll_installed_apps: false`.
- **Crecimiento del log:** `events.json` se appendea indefinidamente; para algo
  permanente, sumar un logrotate.
- **No pases secretos por línea de comandos** en este host: `journald` registra
  los comandos de `sudo` y la regla 5402 los convierte en alertas, con lo cual
  terminarían en `alerts.json`.
- **Rotar el secret** al cerrar el POC (Global Settings → API Credentials
  Management): estuvo pegado en chats y embebido en `setup-remote.sh`.

## Pendiente

- Confirmar el payload real de `compliance-violations` y de eventos Android
  cuando haya un dispositivo Android enrolado; después apretar las reglas
  1006[3x] a las claves reales.
- `installed-apps` no trae versión de app (al menos en Windows). Si en Android sí
  viene, se pueden agregar reglas de versiones vulnerables.
- Si `mobile/v1/devices` devuelve 403/404 en otro tenant, la Mobile API no está
  habilitada; el script lo loguea y sigue con la SIEM API.

## Archivos

| Archivo | Qué es |
| --- | --- |
| `integration/custom-sophos-mobile.py` | La integración (corre como command wodle cada 5 min) |
| `rules/sophos_mobile_rules.xml` | 42 reglas, IDs 100600-100649 |
| `wazuh/ossec_conf_snippet.xml` | Bloques `<wodle>` + `<localfile>` de referencia |
| `deploy.sh` | Genera la config, copia todo y ejecuta el instalador por SSH |
| `setup-remote.sh` | Instalador que corre como root en el manager |
| `credentials.env.example` | Plantilla de credenciales (copiar a `credentials.env`) |
| `dashboard/make_dashboard.py` | Genera los saved objects del dashboard |
| `dashboard/load-dashboard.sh` | Importa el dashboard vía API |
| `dashboard/sophos-mobile-dashboard.ndjson` | Saved objects generados |
| `tests/rule-tests.sh` | 44 tests de reglas con `wazuh-logtest` |

**Las credenciales no están en el repo.** `credentials.env` está en `.gitignore`;
solo se versiona la plantilla.

## Licencia

Copyright (C) 2026 Gerardo Cáceres

Este programa es software libre: podés redistribuirlo y/o modificarlo bajo los
términos de la **GNU General Public License version 2** publicada por la Free
Software Foundation. Ver [LICENSE](LICENSE) para el texto completo.

Se distribuye con la esperanza de que sea útil, pero **SIN NINGUNA GARANTÍA**,
ni siquiera la garantía implícita de comerciabilidad o aptitud para un propósito
particular.

GPLv2 es la misma licencia que usa Wazuh, así que el código es compatible con el
ruleset y las integraciones del proyecto.

## Referencias

- [Sophos Central SIEM Integration (oficial)](https://github.com/sophos/Sophos-Central-SIEM-Integration)
- [Sophos SIEM API](https://developer.sophos.com/docs/siem-v1/1/overview)
- [Event y alert types de la API](https://support.sophos.com/support/s/article/KBA-000006285)
- [Available compliance rules (Sophos Mobile)](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/CompliancePolicies/AvailableComplianceRules/)
- [Mobile Threat Defense compliance rules](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/MTDWithIXM/ComplianceRules/index.html)
