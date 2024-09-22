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
import boto3
import cv2
import numpy as np
import tensorflow as tf
from werkzeug.exceptions import BadRequest
from datetime import timedelta
import hashlib
import pyttsx3
import tempfile
import gc
import psutil
# Configuración del logging
logging.basicConfig(level=logging.INFO)

def log_memory_usage():
    process = psutil.Process()  # Obtén el proceso actual
    mem_info = process.memory_info()  # Información de memoria
    logging.info(f"Uso de memoria: {mem_info.rss / 1024 ** 2:.2f} MB")  # RSS en MB

# Configuración de Flask y JWT
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://signab0t.s3-website-us-east-1.amazonaws.com"}}, allow_headers=["Authorization", "Content-Type"])


app.config['JWT_SECRET_KEY'] = 'cheeetos3'  # Cambia esto por una clave secreta
app.config['SECRET_KEY'] = 'cheetos3'  # Necesario para la protección CSRF
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

jwt = JWTManager(app)
csrf = CSRFProtect(app)

# Funciones de hash para correos electrónicos
def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

# Nombre de tu bucket de S3 y el archivo a descargar
bucket_name = 'archbackend'
model_file_key = 'gesture_recognition_model.h5'

# Ruta local donde guardarás el archivo descargado temporalmente
local_model_path = '/tmp/gesture_recognition_model.h5'

# Crear un cliente S3 usando boto3
s3 = boto3.client('s3')

# Descargar el archivo desde S3
def download_model_from_s3():
    if not os.path.exists(local_model_path):
        print(f"Descargando {model_file_key} desde S3...")
        s3.download_file(bucket_name, model_file_key, local_model_path)
        print("Descarga completa.")
    else:
        print("El modelo ya está descargado.")

# Llamar la función para descargar el modelo
download_model_from_s3()

# Cargar el modelo en TensorFlow
model = tf.keras.models.load_model(local_model_path)
logging.info("Modelo cargado.")
print("Modelo cargado.")

# Conectar a MongoDB
client = MongoClient('mongodb+srv://carlosperez0390:cheetos3@signabot.qd4ab.mongodb.net/?retryWrites=true&w=majority&appName=Signabot',
                    serverSelectionTimeoutMS=5000,  
    socketTimeoutMS=5000 
    )
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
def log_access( action):
    log_entry = {
       
        'action': action,
        'timestamp': time.time()
    }
    access_logs_collection.insert_one(log_entry)
    logging.info(f"Acceso registrado: Acción: {action}")
    
def log_access_login(user_id, action):
    log_entry = {
        'user_id': user_id,  # Agrega el user_id al registro
        'action': action,
        'timestamp': time.time()
    }
    access_logs_collection.insert_one(log_entry)
    logging.info(f"Acceso registrado: Usuario: {user_id}, Acción: {action}")

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
            log_access_login(user['_id'], 'login')
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
@csrf.exempt  # Si deseas desactivar CSRF para esta ruta específica
def predict():
    start_time = time.time()
    log_memory_usage()
    logging.info("Solicitud de predicción recibida.")

    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        image_path = temp_file.name
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
    del img  # Libera la variable grande
    gc.collect()  # Fuerza la recolección de basura

    # Guardar en MongoDB
    prediction_record = {
        'filename': filename,
        'predicted_label': predicted_label,
        'confidence': confidence,
        'timestamp': time.time()
    }
    predictions_collection.insert_one(prediction_record)

    log_access('predict')

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
