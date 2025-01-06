from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime

# Conexión a la base de datos
client = MongoClient("mongodb://localhost:27017/")
db = client["inventory"]

def insert_or_update_device(device_data):
    """Inserta o actualiza la información de un dispositivo."""
    try:
        # Validar datos de entrada
        if "device_id" not in device_data:
            raise ValueError("El campo 'device_id' es obligatorio")

        # Convertir el ID a ObjectId si es válido
        device_id = device_data["device_id"]
        device_data["last_update"] = datetime.now()  # Timestamp de actualización

        # Realizar el upsert
        result = db.devices.update_one(
            {"device_id": device_id},
            {"$set": device_data},
            upsert=True
        )

        if result.upserted_id:
            return {"message": "Nuevo dispositivo insertado correctamente"}
        elif result.modified_count > 0:
            return {"message": "Dispositivo actualizado correctamente"}
        else:
            return {"message": "El dispositivo ya estaba actualizado sin cambios"}
    except Exception as e:
        raise Exception(f"Error al insertar o actualizar el dispositivo: {str(e)}")

def get_device_by_id(device_id):
    """Obtiene un dispositivo por su ID."""
    try:
        device = db.devices.find_one({"device_id": device_id})
        if not device:
            raise ValueError(f"Dispositivo con ID {device_id} no encontrado")

        # Convertir ObjectId a cadena para compatibilidad JSON
        device["_id"] = str(device["_id"])
        return device
    except Exception as e:
        raise Exception(f"Error al obtener el dispositivo con ID {device_id}: {str(e)}")

def get_all_devices():
    """Obtiene todos los dispositivos registrados."""
    try:
        devices = list(db.devices.find())
        if not devices:
            raise ValueError("No se encontraron dispositivos registrados")

        # Convertir ObjectId a cadena para todos los documentos
        for device in devices:
            device["_id"] = str(device["_id"])
        return devices
    except Exception as e:
        raise Exception(f"Error al obtener los dispositivos: {str(e)}")
