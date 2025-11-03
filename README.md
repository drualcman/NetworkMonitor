# Network Security Monitor

Un monitor de seguridad avanzado para Windows que detecta conexiones de red sospechosas, servicios escuchando en puertos no autorizados y procesos no whitelisted.

##  Características

-  **Monitoreo en tiempo real** de servicios escuchando
-  **Detección de conexiones entrantes** sospechosas  
-  **Análisis de procesos** con conexiones de red
-  **Alertas sonoras** para diferentes tipos de amenazas
-  **Configuración personalizable** mediante archivo JSON
-  **Logging automático** de actividades sospechosas

##  Instalación y Uso

### Requisitos
- Windows 10/11
- .NET 9.0 o superior
- Permisos de Administrador

### Ejecución
1. **Descarga** el ejecutable o compila desde código fuente
2. **Ejecuta como Administrador** (necesario para acceso a conexiones de red)
3. **Presiona Q** para salir del monitoreo

```bash
# Ejecutar como administrador
NetworkMonitor.exe

## Configuración
El programa crea automáticamente el archivo security_config.json con esta estructura:

### Archivo de Configuración
```json
{
  "WhitelistedPorts": [
    80, 443, 53, 21, 22, 25, 110, 143,
    5432, 7680, 4767, 53241, 63342, 42050,
    135, 139, 445, 5040,
    49664, 49665, 49666, 49667, 49668, 49669, 49672,
    44321, 44350, 44380, 44399, 59717, 59719, 61989, 61994
  ],
  "WhitelistedProcesses": [
    "chrome", "firefox", "edge", "explorer", "svchost",
    "winlogon", "services", "system", "postgres", "java",
    "code", "devenv", "msedge", "notepad", "taskmgr",
    "wininit", "csrss", "lsass", "smss", "spoolsv",
    "docker", "node", "python", "php",
    "pangps", "embeddings-server", "datagrip64",
    "com.docker.backend", "onedrive.sync.service",
    "slack"
  ],
  "CheckInterval": 5000,
  "LogToFile": true,
  "KnownSuspiciousProcesses": {
    "PanGPS": "GlobalProtect VPN - Corporate software",
    "embeddings-server": "AI Service - Legitimate",
    "datagrip64": "JetBrains DataGrip - Legitimate IDE",
    "com.docker.backend": "Docker Desktop - Legitimate",
    "OneDrive.Sync.Service": "Microsoft OneDrive - Legitimate"
  }
}
```
### Personalización de Configuración
#### Puertos Whitelisted
Agrega puertos que consideres seguros:
```json
"WhitelistedPorts": [
  80,           // HTTP
  443,          // HTTPS
  53,           // DNS
  5432,         // PostgreSQL
  3306,         // MySQL
  8080,         // Desarroll web
  // Agrega tus puertos personalizados aquí
]
```
#### Procesos Whitelisted
Agrega nombres de procesos que consideres seguros:
```json
"WhitelistedProcesses": [
  "chrome",     // Navegadores
  "firefox",
  "explorer",   // Sistema Windows
  "svchost",
  "code",       // Editores/IDEs
  "devenv",
  "docker",     // Contenedores
  "node",       // Desarrollo
  "python",
  // Agrega tus procesos personalizados aquí
]
```
###  Otros Parámetros
- **CheckInterval:** Intervalo de escaneo en milisegundos (recomendado: 5000)
- **LogToFile:** Habilitar/deshabilitar logging a network_security.log

## Qué Detecta el Monitor
### Alertas Críticas (Sonido: Doble Beep Grave)
- Servicios escuchando en puertos no whitelisted
- Procesos desconocidos escuchando en cualquier puerto
- PowerShell escuchando en puertos altos
### Alertas de Advertencia (Sonido: Beep Medio)
- Conexiones entrantes establecidas desde internet
- Procesos no whitelisted con actividad de red
### Alertas Informativas (Sonido: Beep Agudo)
- Procesos conocidos con conexiones entrantes
- Actividad inusual de procesos whitelisted

## Salida del Programa
```text
- SERVICIOS ESCUCHANDO:
--    Puerto: 5432 - Proceso: com.docker.backend
--    Puerto: 4767 - Proceso: PanGPS
--     PUERTO SOSPECHOSO: 1337
--      Proceso: powershell (PID: 28528)
--      Dirección: 0.0.0.0

- CONEXIONES ESTABLECIDAS ENTRANTES:
--    No hay conexiones entrantes establecidas

- PROCESOS CON CONEXIONES DE RED:
--    Proceso: chrome (PID: 1234)

- PROCESOS CONOCIDOS CON CONEXIONES ENTRANTES:
--    No hay procesos conocidos con conexiones entrantes
```

## Solución de Problemas
### El programa no detecta conexiones
- Ejecuta como Administrador
- Verifica que el firewall no bloquee la aplicación 
### No se reproducen sonidos
- Los sonidos usan ```Console.Beep()```
- Funciona en la mayoría de sistemas Windows
- Alternativa: Revisa el archivo de log para alertas silenciosas
### Falsos positivos
- Edita ```security_config.json```
- Agrega puertos/procesos legítimos a las whitelists
- Reinicia el monitor
### El archivo de configuración no se crea
- El programa crea automáticamente ```security_config.json``` en el primer inicio
- Si hay errores, se usará la configuración por defecto
## Logging
Las alertas se guardan en ```network_security.log```:
```text
2025-10-29 19:25:03 | Servicio escuchando en puerto no autorizado: 1337 - Proceso: powershell
2025-10-29 19:30:15 | CONEXIÓN ENTRANTE SOSPECHOSA: 192.168.1.50:443 -> 192.168.1.100:50001
```
## Recomendaciones de Seguridad
- **Mantén actualizada** la whitelist de procesos
- **Revisa regularmente** los logs de seguridad
- **No whitelistees PowerShell** a menos que sea estrictamente necesario
- **Monitoriza en segundo plano** durante el uso normal del sistema

# Licencia
Este proyecto es para uso educativo y personal. Úsalo responsablemente.

# Contribuciones
Las contribuciones son bienvenidas. Por favor:
- Reporta falsos positivos con detalles del proceso/puerto
- Sugiere mejoras en la detección
- Comparte whitelists para aplicaciones comunes


