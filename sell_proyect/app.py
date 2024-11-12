from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import desc
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/BD_mejorVendedor'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'tu_clave_secreta'  # Cambia esto por una clave secreta real

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
ma = Marshmallow(app)


from models import Vendedor, CredencialesVendedor , User  # Asegúrate de importar tus modelos aquí
from views import register_bp
register_bp(app)



@app.route("/")
def index():
    return render_template('index.html')

@app.route("/Vendedores", methods=['GET', 'POST'])
def vendedores():
    vendedores = Vendedor.query.all()
    
    if request.method == 'POST':
        pais = request.form['pais']
        cantidad_de_ventas = request.form['cantidad_ventas']
        total_ganancias = request.form['total_ganancias']
        
        if pais and cantidad_de_ventas and total_ganancias:
            try:
                ultimo_vendedor = Vendedor.query.order_by(Vendedor.id_vendedor.desc()).first()
                nuevo_id_vendedor = (ultimo_vendedor.id_vendedor + 1) if ultimo_vendedor else 1

                nuevo_vendedor = Vendedor(
                    id_vendedor=nuevo_id_vendedor,
                    pais=pais,
                    cantidad_de_productos_vendidos=int(cantidad_de_ventas),
                    total_ganado=int(total_ganancias)
                )
                db.session.add(nuevo_vendedor)
                db.session.commit()
                flash('Vendedor agregado exitosamente', 'success')
                return redirect(url_for('vendedores'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error al agregar vendedor: {e}', 'danger')
        else:
            flash('Por favor, complete todos los campos', 'danger')

    return render_template('Vendedores.html', vendedores=vendedores)

from sqlalchemy import select

@app.route("/Credenciales", methods=['POST', 'GET'])
def credenciales():
    # Subconsulta para obtener solo vendedores sin credenciales
    subquery = select(CredencialesVendedor.id_vendedor)
    vendedores_sin_credenciales = Vendedor.query.filter(~Vendedor.id_vendedor.in_(subquery)).all()
    
    credenciales = CredencialesVendedor.query.all()  # Obtener todas las credenciales existentes
    
    if request.method == 'POST':
        id_vendedor = request.form.get('id')
        nombre_usuario = request.form.get('nombre')
        contrasena = request.form.get('contrasena')
        edad = request.form.get('edad')
        correo_contacto = request.form.get('correo')
        
        # Validar datos del formulario
        if id_vendedor and nombre_usuario and contrasena and edad and correo_contacto:
            try:
                nueva_credencial = CredencialesVendedor(
                    id_vendedor=id_vendedor, 
                    nombre_usuario=nombre_usuario, 
                    contrasena=contrasena,
                    edad=edad, 
                    correo_contacto=correo_contacto
                )
                db.session.add(nueva_credencial)
                db.session.commit()
                flash('Credencial de vendedor agregada exitosamente', 'success')
                return redirect(url_for('credenciales'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error al agregar la credencial: {e}', 'danger')
        else:
            flash('Por favor, complete todos los campos.', 'danger')

    # Pasar solo los vendedores sin credenciales y las credenciales al contexto
    return render_template('Credenciales.html', credenciales=credenciales, vendedores=vendedores_sin_credenciales)



@app.route('/mejores_vendedores')
def mostrar_mejores_vendedores():
    # Obtener los mejores vendedores ordenados por total_ganado de mayor a menor
    mejores_vendedores = Vendedor.query.order_by(desc(Vendedor.total_ganado)).all()
    return render_template('mejores_vendedores.html', mejores_vendedores=mejores_vendedores)

if __name__ == "__main__":
    app.run(debug=True)

@app.route("/editar_credencial/<int:id>", methods=['GET', 'POST'])
def editar_credencial(id):
    credencial = CredencialesVendedor.query.get_or_404(id)  # Obtener la credencial por ID

    if request.method == 'POST':
        # Actualiza los campos con los datos del formulario
        credencial.nombre_usuario = request.form['nombre']
        credencial.contrasena = request.form['contrasena']
        credencial.edad = request.form['edad']
        credencial.correo_contacto = request.form['correo']
        
        try:
            db.session.commit()
            flash('Credencial actualizada exitosamente', 'success')
            return redirect(url_for('credenciales'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar la credencial: {e}', 'danger')

    return render_template('editar_credencial.html', credencial=credencial)

@app.route("/editar_vendedor/<int:id>", methods=['GET', 'POST'])
def editar_vendedor(id):
    vendedor = Vendedor.query.get_or_404(id)  # Obtener el vendedor por ID

    if request.method == 'POST':
        # Actualiza los campos con los datos del formulario
        vendedor.pais = request.form['pais']
        vendedor.cantidad_de_productos_vendidos = request.form['cantidad_ventas']
        vendedor.total_ganado = request.form['total_ganancias']
        
        try:
            db.session.commit()
            flash('Vendedor actualizado exitosamente', 'success')
            return redirect(url_for('vendedores'))  # Redirigir a la lista de vendedores
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar el vendedor: {e}', 'danger')

    return render_template('editar_vendedor.html', vendedor=vendedor)
