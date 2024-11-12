from app import ma
from marshmallow import validates, ValidationError
from models import User, Vendedor, CredencialesVendedor 

from sqlalchemy import desc


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    id = ma.auto_field()
    username = ma.auto_field()
    password_hash = ma.auto_field()
    is_admin = ma.auto_field()

    @validates('username')
    def validate_username(self, value):
        user = User.query.filter_by(username=value).first()
        if user:
            raise ValidationError("ya existe un usuario con ese nombre :(")
        return value

class UserMinimalSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    username = ma.auto_field()

class VendedorSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Vendedor
        load_instance = True

    pais = ma.auto_field()
    cantidad_de_productos_vendidos = ma.auto_field()
    total_ganado = ma.auto_field()

class CredencialSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = CredencialesVendedor  # Asegúrate de usar "model" en minúscula
        load_instance = True

    nombre_usuario = ma.auto_field()
    contrasena = ma.auto_field()
    edad = ma.auto_field()
    correo_contacto = ma.auto_field()

class MejoresVendedoresSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Vendedor  # Ahora el modelo principal es Vendedor
        load_instance = True

    # Datos del Vendedor
    id_vendedor = ma.auto_field()
    pais = ma.auto_field()
    cantidad_de_productos_vendidos = ma.auto_field()
    total_ganado = ma.auto_field()

    # Datos de CredencialesVendedor (anidados)
    credencial = ma.Nested(CredencialesVendedor, only=['nombre_usuario', 'correo_contacto'])

