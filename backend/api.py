from flask import Flask, request, jsonify
from controllers.db_conexion import insert_or_update_device, get_device_by_id, get_all_devices
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

@app.route("/", methods=['POST', 'GET'])
def home():
    return "API ACTIVO", 200

# Ruta para recibir datos del agente
@app.route("/api/device", methods=["POST"])
def receive_device_data():
    try:
        # Verificar que el Content-Type es application/json
        if request.content_type != 'application/json':
            return jsonify({"error": "El Content-Type debe ser 'application/json'"}), 415
        
        data = request.get_json()  # Recibimos los datos en formato JSON
        print(f"Datos recibidos: {data}")  # Para verificar que los datos llegan correctamente

        # Verificamos que el 'device_id' esté presente en los datos
        if not data or "device_id" not in data:
            return jsonify({"error": "No se recibieron datos válidos o falta 'device_id'"}), 400
        
        # Insertar o actualizar los datos del dispositivo en la base de datos
        response = insert_or_update_device(data)  # Llamamos a la función para insertar/actualizar

        # Retornamos el mensaje de éxito
        return jsonify({"message": response["message"]}), 200
    except HTTPException as http_error:
        # Manejo de errores específicos de HTTP
        return jsonify({"error": f"HTTP error occurred: {http_error.description}"}), http_error.code
    except Exception as e:
        # Manejo de errores generales
        return jsonify({"error": f"Error al procesar la solicitud: {str(e)}"}), 500

# Ruta para obtener un dispositivo por su ID
@app.route("/api/device/<device_id>", methods=["GET"])
def get_device_data(device_id):
    try:
        device = get_device_by_id(device_id)
        if not device:
            return jsonify({"error": "Dispositivo no encontrado"}), 404
        return jsonify(device), 200
    except HTTPException as http_error:
        # Manejo de errores específicos de HTTP
        return jsonify({"error": f"HTTP error occurred: {http_error.description}"}), http_error.code
    except Exception as e:
        # Manejo de errores generales
        return jsonify({"error": f"Error al procesar la solicitud: {str(e)}"}), 500

# Ruta para obtener todos los dispositivos
@app.route("/api/devices", methods=["GET"])
def get_all_device_data():
    try:
        devices = get_all_devices()
        return jsonify(devices), 200
    except HTTPException as http_error:
        # Manejo de errores específicos de HTTP
        return jsonify({"error": f"HTTP error occurred: {http_error.description}"}), http_error.code
    except Exception as e:
        # Manejo de errores generales
        return jsonify({"error": f"Error al procesar la solicitud: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
