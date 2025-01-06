import psutil
import platform
import os
import socket
import subprocess
import logging
import json
import re
import requests
from datetime import datetime

#Conexion

API_URL = "http://127.0.0.1:5000/api/device"  # Nueva URL del endpoint
JSON_FILE = "system_info.json"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def ejecutar_comando_wmic(comando):
    """Ejecuta un comando WMIC y devuelve el resultado limpio, gestionando errores."""
    try:
        result = subprocess.check_output(comando, shell=True, text=True).strip().split("\n")
        return [line.strip() for line in result if line.strip()]
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al ejecutar el comando '{comando}': {e}")
        return []


def obtener_informacion_usuario():
    """Obtiene información del usuario, dominio, edición y clave de producto."""
    try:
        nombre_usuario = os.getlogin()
        dominio = os.environ.get('USERDOMAIN', 'No disponible')
        version_windows = platform.system() + " " + platform.release()

        # Obtener la edición de Windows
        try:
            output = subprocess.check_output('wmic os get Caption', shell=True, text=True).strip()
            edicion_windows = output.split('\n')[1] if len(output.split('\n')) > 1 else "No disponible"
        except subprocess.CalledProcessError:
            edicion_windows = "No disponible"

        # Obtener la clave del producto
        try:
            clave_producto = subprocess.check_output(
                'powershell "(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey"',
                shell=True, text=True).strip()
        except subprocess.CalledProcessError:
            clave_producto = "No disponible"

        return {
            "Nombre Usuario": nombre_usuario,
            "Dominio": dominio,
            "Versión Windows": version_windows,
            "Edición Windows": edicion_windows,
            "Clave Producto": clave_producto
        }
    except Exception as e:
        logging.error(f"Error al obtener información del usuario: {e}")
        return {
            "Nombre Usuario": "Error",
            "Dominio": "Error",
            "Versión Windows": "Error",
            "Edición Windows": "Error",
            "Clave Producto": "Error"
        }

def obtener_info_dispositivo_windows():
    """Obtiene el modelo, número de serie y nombre de host del dispositivo en sistemas Windows."""
    info = {}
    try:
        # Ejecutar el comando para obtener solo el nombre del modelo del dispositivo
        modelo_info = ejecutar_comando_wmic("wmic csproduct get name")
        if modelo_info and len(modelo_info) > 1:  # Si la salida contiene más de una línea
            info["Modelo"] = modelo_info[1]  # El segundo valor es el nombre del modelo
        else:
            info["Modelo"] = "No disponible"
        
        # Obtenemos el número de serie
        serial_info = ejecutar_comando_wmic("wmic bios get serialnumber")
        if serial_info and len(serial_info) > 1:  # Si la salida contiene más de una línea
            info["Número de serie"] = serial_info[1]
        else:
            info["Número de serie"] = "No disponible"

        # Obtenemos el nombre de host
        info["Nombre de host"] = socket.gethostname()

    except Exception as e:
        logging.error(f"Error al obtener información del dispositivo: {e}")
        return {"Modelo": "Error", "Número de serie": "Error", "Nombre de host": "Error"}

    # Solo retornar los tres campos necesarios
    return {
        "Modelo": info.get("Modelo", "No disponible"),
        "Número de serie": info.get("Número de serie", "No disponible"),
        "Nombre de host": info.get("Nombre de host", "No disponible")
    }

def detect_antivirus():
    """Detecta antivirus instalados basándose en una lista de antivirus comunes."""
    antivirus_list = [
        "Avast", "AVG", "Bitdefender", "Kaspersky", "McAfee", "Trellix", "Norton",
        "Windows Defender", "ESET", "Trend Micro", "Sophos", "Panda", "Comodo"
    ]
    installed_programs = get_installed_programs()

    found_antivirus = [antivirus for antivirus in antivirus_list if any(antivirus in program for program in installed_programs)]
    return found_antivirus or ["No se detectaron antivirus"]

def obtener_version_windows():
    """Obtiene la versión del sistema operativo Windows."""
    if platform.system() == "Windows":
        return platform.version()
    else:
        return "No es Windows"

def obtener_modelo_procesador():
    """Obtiene el modelo comercial del procesador utilizando diferentes métodos."""
    # Método 1: Utilizar platform
    modelo = platform.processor()

    # Método 2: Utilizar wmi (si está instalado)
    try:
        import wmi
        c = wmi.WMI()
        for cpu in c.Win32_Processor():
            modelo = cpu.Name
            break
    except ImportError:
        pass

    # Método 3: Utilizar comandos del sistema (Linux)
    if modelo is None:
        try:
            output = subprocess.check_output(['lscpu']).decode('utf-8')
            match = re.search(r'Model name:\s+(.*)', output)
            if match:
                modelo = match.group(1)
        except subprocess.CalledProcessError:
            pass

    # Si ninguno de los métodos anteriores funciona, devolver la información del CPUID
    if modelo is None:
        modelo = "No se pudo obtener el modelo comercial. Información del CPUID: " + platform.processor()

    return modelo

def obtener_info_redes_psutil():
    """Obtiene información de las interfaces de red del sistema utilizando psutil."""
    info_redes = []
    try:
        interfaces = psutil.net_if_addrs()
        for net_if, addrs in interfaces.items():
            ip = "No disponible"
            mac = "No disponible"
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ip = addr.address
                elif addr.family == psutil.AF_LINK:  # MAC (usamos psutil.AF_LINK como respaldo)
                    mac = addr.address

            info_redes.append({
                'Interfaz': net_if,
                'IP': ip,
                'MAC': mac
            })
    except Exception as e:
        logging.error(f"Error al obtener la información de las redes: {e}")
    
    return info_redes

def get_installed_programs():
    """Obtiene una lista de programas instalados en el sistema operativo."""
    try:
        command = ['wmic', 'product', 'get', 'name']
        result = subprocess.run(command, capture_output=True, text=True)
        programs = result.stdout.splitlines()
        return [program.strip() for program in programs if program.strip() and program != "Name"]
    except Exception as e:
        logging.error(f"Error al obtener programas instalados: {e}")
        return []

def obtener_informacion_sistema():
    """Obtiene información detallada sobre el sistema."""
    info = {
        'cpu_count': psutil.cpu_count(logical=True),
        'cpu_freq': psutil.cpu_freq().max,
        'memory': psutil.virtual_memory().total >> 20,  # Conversión a MB de forma más eficiente
        'disk_partitions': []
    }

    for partition in psutil.disk_partitions():
        usage = psutil.disk_usage(partition.mountpoint)
        info['disk_partitions'].append({
            'device': partition.device,
            'mountpoint': partition.mountpoint,
            'fstype': partition.fstype,
            'total_gb': usage.total >> 30,  # Conversión a GB de forma más eficiente
            'used_gb': usage.used >> 30,
            'free_gb': usage.free >> 30,
            'percent': usage.percent
        })

    return info

def obtener_espacio_total_disco(info):
    """Calcula el espacio total en disco a partir de la información del sistema."""
    espacio_total = 0
    for partition in info['disk_partitions']:
        espacio_total += partition['total_gb']
    return espacio_total

device_id = obtener_informacion_usuario().get("Nombre Usuario", "Desconocido")

def collect_system_info():
    """Recolecta toda la información del sistema organizada por categorías."""
    sistema_info = obtener_informacion_sistema()
    espacio_total = obtener_espacio_total_disco(sistema_info)

    return {
        "device_id": device_id,
        "Fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "SO": obtener_informacion_usuario(),
        "Hardware": {
            "Procesador": {
                "Modelo": obtener_modelo_procesador(),
                "Frecuencia CPU (MHz)": sistema_info['cpu_freq'],
                "Número de CPU": sistema_info['cpu_count']
            },
            "RAM": {
                "Memoria Total (MB)": sistema_info['memory']
            },
            "Disco Duro": {
                "Espacio Total en Disco (GB)": espacio_total,
                "Particiones de Disco": sistema_info['disk_partitions']
            }
        },
        "Software": {
            "Programas Instalados": get_installed_programs()
        },
        "Antivirus": {
            "Antivirus Detectados": detect_antivirus()
        },
        "Redes": {
            "Interfaces de Red": obtener_info_redes_psutil()
        }
    }



def save_to_json_file(data, filename="system_info.json"):
    """Guarda los datos recolectados en un archivo JSON."""
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
        logging.info(f"Datos almacenados correctamente en {filename}")
    except Exception as e:
        logging.error(f"Error al guardar datos en JSON: {e}")

def send_data_to_api(data):
    """Envía los datos recolectados a la API."""
    try:
        logging.info(f"Enviando los siguientes datos a la API: {json.dumps(data, indent=4)}")  # Log de los datos enviados
        response = requests.post(API_URL, json=data)
        if response.status_code == 200:
            logging.info("Datos enviados correctamente a la API.")
        else:
            logging.warning(f"Error al enviar datos a la API. Código de estado: {response.status_code}")
            logging.warning(f"Respuesta de la API: {response.text}")  # Respuesta de error de la API
    except Exception as e:
        logging.error(f"Error al enviar datos a la API: {e}")


if __name__ == "__main__":
    # Recolectar información
    system_info = collect_system_info()

    # Guardar en archivo JSON
    save_to_json_file(system_info)

    # Enviar a la API
    send_data_to_api(system_info)
    #send_data_to_api()