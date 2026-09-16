# LAN-Guardian

LAN-Guardian es una pequeña herramienta defensiva de monitorización de redes para redes locales
IPv4. Envía periódicamente peticiones ARP, registra las observaciones de IP/MAC en una base de
datos local SQLite, identifica los fabricantes comunes de MAC/OUI y lanza alertas cuando se
observa una dirección MAC por primera vez. La elaboración de esta herramienta es sobretodo, para aprendizaje personal.

El proyecto es intencionalmente modular:

```text
LAN-Guardian/
├── main.py
├── requirements.txt
├── README.md
├── network.db                  # created at runtime
└── src/
    ├── __init__.py
    ├── scanner.py              # ARP discovery
    ├── database.py             # SQLite persistence
    ├── vendor.py               # OUI/vendor + privacy heuristics
    └── notifier.py             # console/Discord/Telegram
```

## Instalación

Python 3.10+ es lo más recomendado.

### Linux

Creamos un entorno virtual e instalamos las dependencias:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

La generación de paquetes ARP normalmente requiere privilegios de red de bajo nivel
(raw-network). El despliegue más sencillo es:

```bash
sudo .venv/bin/python main.py --interface eth0 --subnet 192.168.1.0/24
```

En Linux, una configuración de privilegios mínimos puede utilizar las capacidades relevantes
como `CAP_NET_RAW` (y, dependiendo del host/ruta de Scapy, `CAP_NET_ADMIN`) en lugar del usuario
root completo. Los requisitos exactos de capacidades varían según el núcleo (kernel), la
interfaz y el backend de captura de paquetes.

### Windows

Ejecute desde una terminal elevada. El soporte de envío/captura de paquetes de Scapy puede
requerir que el controlador Npcap esté instalado. Utilice un nombre de interfaz aceptado por
Scapy.

### macOS

Ejecute con los privilegios necesarios para el acceso a paquetes de bajo nivel. Dependiendo de
la configuración de seguridad de macOS, es posible que se necesiten permisos adicionales de
captura de paquetes o de red.

## Uso

Escaneo único:

```bash
sudo python3 main.py \
  --interface eth0 \
  --subnet 192.168.1.0/24 \
  --mode once
```

Monitorización continua cada 60 segundos:

```bash
sudo python3 main.py \
  --interface eth0 \
  --subnet 192.168.1.0/24 \
  --interval 60 \
  --mode loop
```

La CLI escribe `network.db` en el directorio de trabajo por defecto. Se puede cambiar con `--db`.

Opciones útiles:

```text
--interface IFACE
--subnet CIDR
--interval SECONDS
--mode {once,loop}
--db PATH
--timeout SECONDS
--retry COUNT
--vendor-api
--discord-webhook URL
--telegram-bot-token TOKEN
--telegram-chat-id CHAT_ID
-v / --verbose
```

También se admiten las siguientes variables de entorno:

```bash
export LAN_GUARDIAN_INTERFACE=eth0
export LAN_GUARDIAN_SUBNET=192.168.1.0/24
export LAN_GUARDIAN_INTERVAL=60
export LAN_GUARDIAN_DB=network.db

# Notificaciones opcionales:
export LAN_GUARDIAN_DISCORD_WEBHOOK='https://discord.com/api/webhooks/...'
export LAN_GUARDIAN_TELEGRAM_BOT_TOKEN='...'
export LAN_GUARDIAN_TELEGRAM_CHAT_ID='...'
```

## Modelo de detección

Una dirección MAC es la identidad principal del dispositivo en la base de datos. Para cada
observación ARP:

1. Se inserta una nueva MAC con `first_seen`, `last_seen`, IP, vendor, and status `new`.
2. Una MAC previamente conocida actualiza su `last_seen` y su IP actual, y se marca como
`known`.
3. Cada observación se almacena adicionalmente en `sightings`, proporcionando un historial
ligero.
4. Solo las detecciones por primera vez activan notificaciones.

Esta es una base práctica más que un sistema completo de inventario de activos. La identidad
basada en MAC es intencionalmente simple porque ARP solo expone una identidad de Capa 2 tal como
la observa la red local.

## Gestión de fabricantes y MACs de privacidad

`src/vendor.py` contiene un pequeño mapa local de OUI para fabricantes comunes y puede consultar
opcionalmente la API pública de `macvendors.com` para OUI desconocidos:

```bash
sudo python3 main.py \
  --interface eth0 \
  --subnet 192.168.1.0/24 \
  --vendor-api
```

Las consultas remotas están deshabilitadas por defecto para que un escaneo no revele
implícitamente las direcciones MAC observadas a un tercero.

El módulo también comprueba el bit de administración local (U/L) en el primer octeto de la MAC.
Una MAC administrada localmente se reporta como una posible dirección de privacidad/aleatoria.
Esto es una heurística, no una prueba definitiva: las direcciones administradas localmente
también pueden ser utilizadas por virtualización, contenedores, tarjetas de red configuradas
manualmente, sistemas Wi-Fi empresariales y otros mecanismos legítimos.

## Consideraciones de seguridad y omisiones conocidas (Bypasses)

### ARP es intrínsecamente local

El descubrimiento ARP opera dentro de un dominio de difusión de Capa 2. Una subred enrutada a través de una puerta de enlace (gateway) no es equivalente a un segmento
de difusión. Por lo tanto, LAN-Guardian puede pasar por alto dispositivos que están:

- Destrás de un router o límite de la capa 3 (L3);
- Aislados en otra VLAN;
- Conectados a una red inalámbrica con aislamiento de clientes;
- Inactivos (sleep) y sin responder a ARP;
- configurados para no responder a ARP de una forma que Scapy pueda observar.

Para una mayor cobertura, combine LAN-Guardian con tablas CAM de
switches, registros DHCP, telemetría de controladores inalámbricos,
registros DNS o inventario de endpoints.

### MAC spoofing

Un host puede cambiar o suplantar (spoof) intencionalmente su MAC de origen. Debido a que LAN-Guardian basa la detección de nuevos dispositivos en la MAC, el spoofing
puede:

- Hacer que un dispositivo parezca otro;
- Crear identidades "nuevas" repetidas si el host rota las direcciones;
- Burlar listas blancas ingenuas basadas únicamente en OUI/MAC.

Trate la MAC como un identificador de red observado, no como una identidad criptográfica.

### Direcciones MAC aleatorias/privadas

Los dispositivos móviles modernos utilizan frecuentemente direcciones MAC de privacidad/aleatorias en Wi-Fi. Por lo tanto, un teléfono puede aparecer con una MAC
diferente a lo largo del tiempo, incluso siendo el mismo dispositivo físico.

LAN-Guardian marca el bit administrado localmente como una **posible** MAC de privacidad, pero no puede correlacionar de manera fiable todas las direcciones aleatorias
con un solo dispositivo. La correlación requiere telemetría adicional y debe diseñarse con los controles de privacidad adecuados.

### Virtualización y contenedores

Las máquinas virtuales, contenedores, hipervisores, puentes (bridges) y dispositivos de seguridad pueden utilizar legítimamente MACs administradas localmente o
sintéticas. Por lo tanto, la clasificación por OUI es una característica de enriquecimiento, no una decisión de autorización.

### Caché ARP y comportamiento del endpoint

Una máquina no tiene por qué exponer todas sus interfaces de red o servicios simplemente porque aparece en un barrido ARP. Por el contrario, la presencia ARP no
demuestra que el host sea un dispositivo no gestionado o "Shadow IT".

Utilice múltiples señales antes de tomar cualquier acción de remediación automatizada.

### Consideraciones sobre escaneo activo

El sondeo ARP es tráfico de red activo. En entornos gestionados:

- Obten autorización del propietario de la red;
- Mantenga el alcance del escaneo limitado a los segmentos locales aprobados;
- Elija un intervalo apropiado para el entorno;
- Evita barridos innecesariamente largos o demasiado frecuentes;
- Espere que las herramientas de IDS/IPS de la red observen la actividad ARP.

### Seguridad de las notificaciones

Las credenciales de Discord y Telegram son secretos de tipo portador (bearer secrets). No los codifique directamente en el código fuente.

Utilice variables de entorno o un gestor de secretos, restrinja los permisos de procesos/archivos y rote los tokens/webhooks filtrados con prontitud. LAN-Guardian no
cifra su base de datos SQLite; proteja el archivo de base de datos con controles de acceso normales a nivel de host.

### Retención de datos y privacidad

`network.db` almacena direcciones IP, direcciones MAC, marcas de tiempo y metadatos de fabricantes. Estos pueden ser datos operativos sensibles. Establezca un período
de retención adecuado y permisos de sistema de archivos para su entorno.


## Solución de problemas

### "Privilegios Insuficientes"

Ejecute el programa con los permisos de red de bajo nivel apropiados. En Linux, verifique la interfaz y las capacidades de los sockets de paquetes. En Windows,
verifique Npcap y la elevación de privilegios.

### No se detectan hosts

Compruebe:

```bash
ip addr
```

Confirme que `--interface` and `--subnet` describen el mismo dominio de difusión local. Pruebe la interfaz con Scapy de forma independiente si es necesario.

### Un dispositivo aparece repetidamente como nuevo

Esto suele ser causado por:

- Aleatorización de MAC;
- MAC spoofing;
- Una interfaz virtual que cambia de identidad;
- Un segundo dispositivo que utiliza la misma identidad inesperadamente.

Inspeccione el historial de `sightings` y correlaciónelo con los datos del servidor DHCP o del controlador Wi-Fi.

## Alcance

LAN-Guardian es un componente de monitorización defensiva. No es un sistema NAC, un IDS/IPS, un escáner de vulnerabilidades ni un inventario definitivo de activos. Su
salida debe alimentar flujos de trabajo de respuesta y visibilidad de red más amplios.
