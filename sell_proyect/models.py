from app import db
from sqlalchemy import desc
class AlembicVersion(db.Model):
    __tablename__ = 'alembic_version'
    
    version_num = db.Column(db.String(32), primary_key=True)

class CredencialesVendedor(db.Model):
    __tablename__ = 'credenciales_vendedor'
    
    id_vendedor = db.Column(db.Integer, db.ForeignKey('vendedor.id_vendedor'), primary_key=True)
    nombre_usuario = db.Column(db.String(50), nullable=False, unique=True)
    contrasena = db.Column(db.String(100), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    correo_contacto = db.Column(db.String(100), nullable=False, unique=True)

    vendedor = db.relationship("Vendedor", backref=db.backref("credenciales", uselist=False))

class Vendedor(db.Model):
    __tablename__ = 'vendedor'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_vendedor = db.Column(db.Integer, nullable=False, unique=True)
    pais = db.Column(db.String(50), nullable=False)
    cantidad_de_productos_vendidos = db.Column(db.Integer, nullable=False)
    total_ganado = db.Column(db.Integer, nullable=False)

    def __str__(self) -> str:
        return f"Vendedor {self.id_vendedor} de {self.pais}: {self.cantidad_de_productos_vendidos} productos vendidos, total ganado {self.total_ganado}"


class MejoresVendedores:
    @staticmethod
    def obtener_mejores_vendedores():
        # Consulta para obtener los vendedores en orden de mayor a menor total ganado
        return Vendedor.query.order_by(desc(Vendedor.total_ganado)).all()


class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(50),nullable = False)
    password_hash = db.Column(db.String(300),nullable = False)
    is_admin = db.Column (db.Boolean)

    def to_dict(self):
        return dict(
            username=self.username,
            password=self.password_hash
        )    