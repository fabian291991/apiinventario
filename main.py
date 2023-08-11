from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret" # Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401


# Funcion que se ejecutará siempre de primero antes de que la consulta llegue a la ruta solicitada
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint, metodo, idRol):

    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)

    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso

@app.route("/almacenistas", methods=['GET'])
def getAlmacenistas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenistas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/almacenistas", methods=['POST'])
def crearAlmacenista():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenistas'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/almacenistas/<string:id>", methods=['GET'])
def getAlmacenista(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenistas/' + id
    response = requests.get(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/almacenistas/<string:id>", methods=['PUT'])
def modificarAlmacenista(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenistas/'+ id
    response = requests.pust(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/almacenistas/<string:id>", methods=['DELETE'])
def eliminarAlmacenista(id):

    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/almacenistas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#############################Producto##########################
@app.route("/productos", methods=['GET'])
def getproductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/productos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/productos", methods=['POST'])
def crearProductos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + 'productos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/productos/<string:id>", methods=['GET'])
def getProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/productos/' + id
    response = requests.get(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['PUT'])
def modificarProducto(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/productos/'+ id
    response = requests.pust(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['DELETE'])
def eliminarProducto(id):

    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/productos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##################################Proveedor################################

@app.route("/proveedores", methods=['GET'])
def getProveedores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedores'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/proveedores", methods=['POST'])
def crearProveedor():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + 'proveedores'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/proveedores/<string:id>", methods=['GET'])
def getProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedores/' + id
    response = requests.get(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedores/<string:id>", methods=['PUT'])
def modificarProveedor(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedores/'+ id
    response = requests.pust(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedores/<string:id>", methods=['DELETE'])
def eliminarProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/proveedores/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

################################################Inventario##################

@app.route("/inventarios", methods=['GET'])
def getInventarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inventarios", methods=['POST'])
def crearInventario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + 'inventarios'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/inventarios/<string:id>", methods=['GET'])
def getInventario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarios/' + id
    response = requests.get(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarios/<string:id>", methods=['PUT'])
def modificarInventario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarios/'+ id
    response = requests.pust(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarios/<string:id>", methods=['DELETE'])
def eliminarInventario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#############################inventario-producto##########################
@app.route("/inventarioproductos", methods=['GET'])
def getInventariosProductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproductos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/inventarioproductos", methods=['POST'])
def crearInventarioProductos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + 'inventarioproductos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/inventarioproductos/<string:id>", methods=['GET'])
def getInventarioProductos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproductos/' + id
    response = requests.get(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproductos/<string:id>", methods=['PUT'])
def modificarInventarioProductos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproductos/'+ id
    response = requests.pust(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/inventarioproductos/<string:id>", methods=['DELETE'])
def eliminarInventarioProductos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/inventarioproductos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)
def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] +
":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
