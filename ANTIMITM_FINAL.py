import os
import time
import psutil
from scapy.all import *
from threading import Thread

# Configuración para utilizar conf.L3socket en lugar de la capa 2 directamente (Librería libpcap)
conf.use_pcap = True

# Tabla ARP de dispositivos confiables, esta pueden cambiar segun la red conectada
dispositivos_confiables = {
    "192.168.1.1": "08:33:ed:90:30:f0",
    "192.168.1.37": "14:13:33:a7:37:69",
    "192.168.1.255": "ff:ff:ff:ff:ff:ff",
    "224.0.0.2": "01:00:5e:00:00:02",
    "224.0.0.22": "01:00:5e:00:00:16",
    "224.0.0.251": "01:00:5e:00:00:fb",
    "224.0.0.252": "01:00:5e:00:00:fc",
    "239.255.255.250": "01:00:5e:7f:ff:fa",
    "255.255.255.255": "ff:ff:ff:ff:ff:ff"
}

# Función para obtener la dirección MAC de una IP
def obtener_mac(ip):
    respuesta, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
    for _, r in respuesta:
        return r[Ether].src
    return None

# Función para bloquear el tráfico del atacante
def bloquear_atacante(ip):
    os.system(f"netsh advfirewall firewall add rule name=\"Bloquear {ip}\" dir=in action=block remoteip={ip}")
    print(f"⚠️ ¡Tráfico bloqueado desde {ip}!")

# Función para detectar ARP Spoofing
def detectar_arp_spoofing(pkt):
    if pkt.haslayer(ARP) and (pkt[ARP].op == 1 or pkt[ARP].op == 2): # Filtro de paquetes arp y ARPs recepcionados de request y replay
        try:
            mac_real = dispositivos_confiables[pkt[ARP].psrc]
            mac_respuesta = obtener_mac(pkt[ARP].psrc)

            if mac_real != mac_respuesta: 
                print(f"⚠️ ¡ALERTA! Posible ataque de ARP Spoofing detectado desde {pkt[ARP].psrc} ({mac_respuesta})")
                bloquear_atacante(pkt[ARP].psrc)
        except KeyError: 
            print(f"⚠️ ¡ALERTA! IP desconocida detectada: {pkt[ARP].psrc}")
            bloquear_atacante(pkt[ARP].psrc)

# Función para iniciar la detección
def iniciar_deteccion():
    print("Iniciando detección de ARP Spoofing...")
    sniff(filter="arp", prn=detectar_arp_spoofing, store=0)

# Iniciar la detección en un hilo separado
thread = Thread(target=iniciar_deteccion)
thread.start()
