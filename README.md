# Sniffer e IDS básico con Scapy

Sniffer de paquetes en **Python + Scapy** que captura tráfico en tiempo real, muestra estadísticas por protocolo y realiza **detección básica de ataques** como **ARP spoofing**, **SYN flood** y **escaneo de puertos**.

> ⚠️ **Usa este software solo en redes propias o con autorización explícita.** Sniffear tráfico puede ser ilegal o violar políticas de uso.

---

## 🧰 Requisitos

- **Python 3.8+**
- **Scapy**
- Permisos para abrir sockets RAW:
  - **Linux/macOS:** ejecutar como `root`/`sudo`, o asignar *capabilities* al intérprete.
  - **Windows:** ejecutar como Administrador e instalar **Npcap**.

### Instalación rápida

```bash
# Linux / macOS
python3 -m pip install --upgrade pip
python3 -m pip install scapy

# Windows (además instala Npcap desde https://npcap.com)
py -m pip install --upgrade pip
py -m pip install scapy
