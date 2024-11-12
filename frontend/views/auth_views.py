from datetime import timedelta
from flask import Blueprint, request, jsonify , make_response
from flask_jwt_extended import (
    create_access_token,
     jwt_required, 
     get_jwt)
from werkzeug.security import (
    check_password_hash, generate_password_hash
    )
from app import db


from models import User , Vendedor, CredencialesVendedor
from schemas import UserSchema , UserMinimalSchema ,MejoresVendedoresSchema

from sqlalchemy import desc


from datetime import timedelta
from flask import Blueprint, request, jsonify , make_response
from flask_jwt_extended import (
    create_access_token,
    jwt_required, 
    get_jwt
)
from werkzeug.security import (
    check_password_hash, generate_password_hash
)
from app import db
from models import User, Vendedor, CredencialesVendedor  # Asegúrate de importar CredencialesVendedor
from schemas import UserSchema, UserMinimalSchema, MejoresVendedoresSchema
from sqlalchemy import desc

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.authorization
    username = data.username if data else None
    password = data.password if data else None

    usuario = User.query.filter_by(username=username).first()

    if usuario and check_password_hash(
        pwhash=usuario.password_hash, password=password
    ):
        access_token = create_access_token(
            identity=username,
            expires_delta=timedelta(minutes=10),
            additional_claims={
                'administrador': usuario.is_admin
            }
        )
        return jsonify({'Token': f'Bearer {access_token}'})

    return jsonify({"Mensaje": "El usuario y la contraseña no coinciden"}), 401

@auth_bp.route('/users', methods=['GET', 'POST'])
@jwt_required()
def users():
    additional_data = get_jwt()
    administrador = additional_data.get('administrador')

    if request.method == 'POST':
        if administrador:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            data_a_validar = dict(
                username=username,
                password_hash=password,
                is_admin=False
            )
            errors = UserSchema().validate(data_a_validar)
            if errors:
                return make_response(jsonify(errors), 400)

            try:
                nuevo_usuario = User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    is_admin=False,
                )
                db.session.add(nuevo_usuario)
                db.session.commit()
                return jsonify({
                    'mensaje': 'Usuario creado correctamente',
                    'Usuario': nuevo_usuario.to_dict()
                })
            except Exception as e:
                return jsonify({
                    'mensaje': 'Error en la creación del usuario',
                    'error': str(e)
                }), 500
        else:
            return jsonify({"Mensaje": "El usuario no es admin"}), 403

    usuarios = User.query.all()
    if administrador:
        return UserSchema(many=True).dump(usuarios)
    else:
        return UserMinimalSchema(many=True).dump(usuarios)


@auth_bp.route('/mejores_vendedores', methods=['GET'])
def obtener_mejores_vendedores():
    # Consulta para obtener los vendedores con las credenciales relacionadas
    mejores_vendedores = Vendedor.query.join(CredencialesVendedor).order_by(desc(Vendedor.total_ganado)).all()

    # Serializa los datos usando MejoresVendedoresSchema
    schema = MejoresVendedoresSchema(many=True)
    result = schema.dump(mejores_vendedores)
    return jsonify(result)


@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    additional_data = get_jwt()
    administrador = additional_data.get('administrador')

    if not administrador:
        return jsonify({"Mensaje": "El usuario no es admin"}), 403
    
    # Obtener el usuario desde la base de datos
    usuario = User.query.get(user_id)
    if not usuario:
        return jsonify({"Mensaje": "Usuario no encontrado"}), 404

    # Obtener los nuevos datos del usuario desde el cuerpo de la solicitud
    data = request.get_json()

    # Validación de los nuevos datos
    username = data.get('username', usuario.username)
    password = data.get('password_hash', usuario.password_hash)  # Si no se pasa una nueva contraseña, mantenemos la actual
    is_admin = data.get('is_admin', usuario.is_admin)

    # Validar si el username ya existe
    existing_user = User.query.filter_by(username=username).first()
    if existing_user and existing_user.id != usuario.id:
        return jsonify({"Mensaje": "El nombre de usuario ya está en uso"}), 400

    # Actualizar los datos del usuario
    usuario.username = username
    if password != usuario.password_hash:  # Solo actualizar la contraseña si es nueva
        usuario.password_hash = generate_password_hash(password)
    usuario.is_admin = is_admin

    try:
        # Guardar los cambios en la base de datos
        db.session.commit()
        return jsonify({
            'mensaje': 'Usuario actualizado correctamente',
            'Usuario': usuario.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'mensaje': 'Error al actualizar el usuario',
            'error': str(e)
        }), 500
@auth_bp.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    # Obtén los datos adicionales del JWT
    additional_data = get_jwt()
    administrador = additional_data.get('administrador')

    # Verifica que el usuario sea administrador
    if not administrador:
        return jsonify({"Mensaje": "El usuario no es admin"}), 403

    # Busca al usuario por su ID
    usuario = User.query.get(id)
    if not usuario:
        return jsonify({"Mensaje": "Usuario no encontrado"}), 404

    try:
        # Eliminar al usuario de la base de datos
        db.session.delete(usuario)
        db.session.commit()

        return jsonify({"Mensaje": f"Usuario con ID {id} eliminado correctamente"}), 200
    except Exception as e:
        return jsonify({"Mensaje": "Error al eliminar el usuario", "Error": str(e)}), 500
