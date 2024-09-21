from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import time
import serial
from pymongo import MongoClient
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
import os
import cv2
import numpy as np
import tensorflow as tf
from werkzeug.exceptions import BadRequest
from datetime import timedelta
import hashlib
import pyttsx3

# Configuración del logging
logging.basicConfig(level=logging.INFO)

# Configuración de Flask y JWT
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Cambia esto por una clave secreta
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Necesario para la protección CSRF
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

jwt = JWTManager(app)
csrf = CSRFProtect(app)

# Funciones de hash para correos electrónicos
def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

# Configuración del modelo
model_path = 'C:/Users/eduar/OneDrive/Documentos/backend/data/gesture_recognition_model.h5'
model = tf.keras.models.load_model(model_path)
logging.info("Modelo cargado.")
print("Modelo cargado.")

# Conectar a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['sign_language_db']
users_collection = db['users']
predictions_collection = db['predictions']
access_logs_collection = db['access_logs']
suspicious_activity_collection = db['suspicious_activity']
logging.info("Conectado a MongoDB.")
print("Conectado a MongoDB.")

# Configuración del puerto serial para la mano robótica
serial_port = 'COM6'
baud_rate = 9600

# Intento de conexión al puerto serial para la mano robótica
try:
    ser = serial.Serial(serial_port, baud_rate)
    logging.info(f"Conectado a la mano robótica en {serial_port} a {baud_rate} baudios.")
    print(f"Conectado a la mano robótica en {serial_port} a {baud_rate} baudios.")
except serial.SerialException as e:
    ser = None
    logging.error(f"No se pudo abrir el puerto serial: {e}")
    print(f"No se pudo abrir el puerto serial: {e}")

# Tamaño de las imágenes
img_size = 224

# Etiquetas de gestos
labels = ['A', 'B', 'C','D','E','F','G','H','I']  

# Funciones de registro de accesos y monitoreo de actividad sospechosa
def log_access(user_id, action):
    log_entry = {
        'user_id': user_id,
        'action': action,
        'timestamp': time.time()
    }
    access_logs_collection.insert_one(log_entry)
    logging.info(f"Acceso registrado: Usuario {user_id}, Acción: {action}")

def log_suspicious_activity(user_id, action):
    log_entry = {
        'user_id': user_id,
        'action': action,
        'timestamp': time.time(),
        'suspicious': True
    }
    suspicious_activity_collection.insert_one(log_entry)
    logging.warning(f"Actividad sospechosa registrada: Usuario {user_id}, Acción: {action}")

def preprocess_image(image_path):
    img = cv2.imread(image_path)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    img = cv2.resize(img, (img_size, img_size))
    img = np.expand_dims(img, axis=0)
    img = img / 255.0
    return img

def preprocess_frame(frame):
    img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    img = cv2.resize(img, (img_size, img_size))
    img = np.expand_dims(img, axis=0)
    img = img / 255.0
    return img

def send_to_robot(letter):
    if ser and ser.is_open:
        try:
            ser.write(letter.encode())
            logging.info(f"Enviado a la mano robótica: {letter}")
            print(f"Enviado a la mano robótica: {letter}")
        except Exception as e:
            logging.error(f"Error al enviar comando a la mano robótica: {e}")
            print(f"Error al enviar comando a la mano robótica: {e}")
    else:
        logging.error("El puerto serial no está disponible.")
        print("El puerto serial no está disponible.")

@app.route('/register', methods=['POST'])
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')  # Establecer 'user' como valor predeterminado

    if not username or not email or not password:
        raise BadRequest("Faltan campos obligatorios")

    email_hashed = hash_email(email)

    if users_collection.find_one({"email": email_hashed}):
        raise BadRequest("El correo electrónico ya está registrado")

    hashed_password = generate_password_hash(password)
    user = {
        "username": username,
        "email": email_hashed,
        "password": hashed_password,
        "role": role
    }

    users_collection.insert_one(user)
    return jsonify({"msg": "Usuario registrado exitosamente"}), 201

@app.route('/login', methods=['POST'])
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    logging.info(f"Intentando iniciar sesión con el correo: {email}")
    email_hashed = hash_email(email)
    user = users_collection.find_one({"email": email_hashed})

    if user:
        logging.info("Usuario encontrado en la base de datos")
        if check_password_hash(user['password'], password):
            logging.info("Contraseña correcta")
            access_token = create_access_token(identity={"username": user['username'], "role": user.get('role', '')})
            log_access(user['_id'], 'login')
            return jsonify(access_token=access_token, role=user.get('role', ''))
        else:
            logging.warning("Contraseña incorrecta")
            log_suspicious_activity(None, f"Intento de inicio de sesión fallido con el correo: {email} (Contraseña incorrecta)")
    else:
        logging.warning("Usuario no encontrado")
        log_suspicious_activity(None, f"Intento de inicio de sesión fallido con el correo: {email} (Usuario no registrado)")

    return jsonify({"msg": "Correo electrónico o contraseña incorrectos"}), 401

@app.route('/logout', methods=['POST'])
@jwt_required()
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def logout():
    user_id = get_jwt_identity()
    log_access(user_id, 'logout')
    return jsonify({"msg": "Sesión cerrada"}), 200

@app.route('/predict', methods=['POST'])
@jwt_required()
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def predict():
    start_time = time.time()
    user_id = get_jwt_identity()

    logging.info("Solicitud de predicción recibida.")

    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    filename = secure_filename(file.filename)
    image_path = os.path.join('C:/Users/eduar/OneDrive/Documentos/backend/images', filename)
    file.save(image_path)

    logging.info("Preprocesando la imagen...")
    img = preprocess_image(image_path)

    logging.info("Haciendo predicción...")
    prediction = model.predict(img)
    confidence = round(float(np.max(prediction)) * 100, 2)
    predicted_label = labels[np.argmax(prediction)]

    response = {
        'label': predicted_label,
        'confidence': f"{confidence}%",
        'processing_time': time.time() - start_time
    }

    # Guardar en MongoDB
    prediction_record = {
        'filename': filename,
        'predicted_label': predicted_label,
        'confidence': confidence,
        'timestamp': time.time()
    }
    predictions_collection.insert_one(prediction_record)

    log_access(user_id, 'predict')

    # Conversión de texto a voz
    engine = pyttsx3.init()
    engine.say(f"La letra es {predicted_label}")
    engine.runAndWait()

    logging.info(f"Predicción realizada: {predicted_label} con {confidence}% de confianza.")

    return jsonify(response)

@app.route('/predict_camera', methods=['POST'])
@jwt_required()
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def predict_camera():
    start_time = time.time()
    user_id = get_jwt_identity()

    logging.info("Solicitud de predicción de cámara recibida.")

    if 'frame' not in request.files:
        return jsonify({'error': 'No frame uploaded'}), 400
    file = request.files['frame']
    frame = np.frombuffer(file.read(), np.uint8)
    frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

    logging.info("Preprocesando el fotograma...")
    img = preprocess_frame(frame)

    logging.info("Haciendo predicción...")
    prediction = model.predict(img)
    confidence = round(float(np.max(prediction)) * 100, 2)
    predicted_label = labels[np.argmax(prediction)]

    response = {
        'label': predicted_label,
        'confidence': confidence,
        'processing_time': time.time() - start_time
    }

    # Guardar en MongoDB
    prediction_record = {
        'predicted_label': predicted_label,
        'confidence': confidence,
        'timestamp': time.time()
    }
    predictions_collection.insert_one(prediction_record)

    log_access(user_id, 'predict_camera')

    # Conversión de texto a voz
    engine = pyttsx3.init()
    engine.say(f"La letra es {predicted_label}")
    engine.runAndWait()

    # Controlar la mano robótica
    send_to_robot(predicted_label)

    return jsonify(response)

# Configuración para HTTPS
if __name__ == '__main__':
    context = ('cert.pem', 'key.pem')  # Reemplaza con las rutas correctas a tus archivos de certificado
    app.run(port=5001, ssl_context=context)