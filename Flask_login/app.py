import random
import re
import string
import psycopg2
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)

app.secret_key = '123456'

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'andesartbol@gmail.com'  # Usa tu correo directamente
app.config['MAIL_PASSWORD'] = 'duzt lmjj jwyv ckim'  # Usa tu contraseña directamente
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return psycopg2.connect(
        dbname="ANDES ARTBOL",
        user="postgres",
        password='123456',  
        host="localhost"
    )

# Decorador para verificar si el usuario está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Ruta principal
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/politicas')
def politicas():
    return render_template('politicas.html')

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        correo = request.form['correo']
        contraseña = request.form['contraseña']

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM Usuarios WHERE correo = %s", (correo,))
            user = cur.fetchone()

            if user and check_password_hash(user[3], contraseña):
                if user[7]:  # Si el usuario está verificado
                    session['usuario_id'] = user[0]
                    session['correo'] = correo  # Guardar el correo en la sesión
                    return redirect(url_for('dashboard'))
                else:
                    error_message = 'Debes verificar tu correo antes de iniciar sesión.'
            else:
                error_message = 'Correo o contraseña incorrectos.'

        except Exception as e:
            error_message = f'Error de conexión a la base de datos: {str(e)}'

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('login.html', error_message=error_message)



# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))


# Ruta del dashboard protegida por el decorador login_required
@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener el nombre del usuario de la base de datos
    cur.execute('SELECT nombre FROM usuarios WHERE usuario_id = %s', (usuario_id,))
    usuario = cur.fetchone()

    # Asegúrate de cerrar el cursor y la conexión
    cur.close()
    conn.close()

    if usuario:
        nombre = usuario[0]  # Asumimos que el nombre está en la primera columna
    else:
        nombre = 'Cliente'  # Cambia esto por el nombre real del usuario

    # Verificar si el usuario es el administrador específico
    is_admin = session.get('correo') == 'dignosebastiangutierrezoropeza@gmail.com'

    return render_template('dashboard.html', nombre=nombre, is_admin=is_admin)



# Ruta para el registro de usuarios
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    # Cargar roles y comunidades antes de la validación
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT rol_id, nombre FROM roles")  # Asumiendo que tienes una tabla 'roles'
    roles = cur.fetchall()

    cur.execute("SELECT comunidad_id, nombre FROM comunidades")  # Asumiendo que tienes una tabla 'comunidades'
    comunidades = cur.fetchall()

    cur.close()
    conn.close()

    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        contraseña = request.form['contraseña']
        telefono = request.form['telefono']
        rol_id = request.form['rol_id']
        comunidad_id = request.form['comunidad_id']

        # Validaciones
        if not nombre or not correo or not contraseña or not telefono or not rol_id or not comunidad_id:
            error_message = 'Todos los campos son obligatorios.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            error_message = 'Correo inválido.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not telefono.isdigit():
            error_message = 'El teléfono debe contener solo números.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not validar_contraseña(contraseña):
            error_message = 'La contraseña debe tener al menos 8 caracteres, incluyendo una mayúscula, una minúscula, un número y un símbolo especial.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        contraseña = generate_password_hash(contraseña)

        # Generar código de verificación
        codigo_verificacion = generar_codigo()

        # Insertar datos en la base de datos
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO usuarios (nombre, correo, contraseña, telefono, rol_id, comunidad_id, codigo_verificacion, verificado) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", 
                (nombre, correo, contraseña, telefono, rol_id, comunidad_id, codigo_verificacion, False)
            )
            conn.commit()

            # Enviar el correo de verificación
            msg = Message('Verificación de cuenta', sender=app.config['MAIL_USERNAME'], recipients=[correo])
            msg.body = f'Tu código de verificación es: {codigo_verificacion}'
            mail.send(msg)

            session['correo_verificacion'] = correo  # Guardar correo en la sesión
            return redirect(url_for('verificar_codigo_registro'))

        except Exception as e:
            error_message = f'Error al registrar el usuario: {str(e)}'
            if conn:
                conn.rollback()

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

    return render_template('registro.html', roles=roles, comunidades=comunidades)

@app.route('/verificar_codigo_recuperacion', methods=['GET', 'POST'])
def verificar_codigo_recuperacion():
    if request.method == 'POST':
        codigo = request.form['codigo']

        if codigo == session.get('codigo'):
            flash('Código verificado correctamente', 'success')
            return redirect(url_for('cambiar_contraseña'))
        else:
            flash('Código incorrecto', 'danger')

    return render_template('verificar_codigo_recuperacion.html')

@app.route('/verificar_codigo_registro', methods=['GET', 'POST'])
def verificar_codigo_registro():
    
        correo = session.get('correo_verificacion')
        
        if request.method == 'POST':
            codigo_ingresado = request.form['codigo']

        # Verificar el código en la base de datos
            conn = None
            cur = None
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT codigo_verificacion FROM usuarios WHERE correo = %s", (correo,))
                codigo_correcto = cur.fetchone()[0]

                if codigo_correcto == codigo_ingresado:
                # Código verificado, actualizar usuario como verificado
                    cur.execute("UPDATE usuarios SET verificado = TRUE WHERE correo = %s", (correo,))
                    conn.commit()
                    flash('Cuenta verificada correctamente.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('El código ingresado es incorrecto.', 'danger')

            except Exception as e:
                flash(f'Error al verificar el código: {str(e)}', 'danger')

            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()
        return render_template('verificar_codigo_registro.html')

# Función para validar la contraseña
def validar_contraseña(contraseña):
    if len(contraseña) < 8:
        return False
    if not any(char.isdigit() for char in contraseña):
        return False
    if not any(char.isupper() for char in contraseña):
        return False
    if not any(char.islower() for char in contraseña):
        return False
    if not any(char in "!@#$%^&*()_+" for char in contraseña):
        return False
    return True

# Ruta para recuperación de contraseña
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        correo = request.form['correo']
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
            user = cur.fetchone()

            if user:
                codigo = generar_codigo()
                session['codigo'] = codigo
                session['usuario_id'] = user[0]

                msg = Message('Código de recuperación', sender=app.config['MAIL_USERNAME'], recipients=[correo])
                msg.html = render_template('correo_codigo.html', codigo=codigo)
                mail.send(msg)
                
                flash('Código de recuperación enviado a tu correo.', 'success')
                print('Se envio el correo pero no se redirige')
                return redirect(url_for('verificar_codigo_recuperacion'))

            else:
                flash('El correo no está registrado.', 'danger')

        except Exception as e:
            flash(f'Error al enviar el código de recuperación: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template('recuperar.html')

# Ruta para cambiar la contraseña
@app.route('/cambiar_contraseña', methods=['GET', 'POST'])
def cambiar_contraseña():
    if request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        usuario_id = session.get('usuario_id')

        nueva_contraseña_hash = generate_password_hash(nueva_contraseña)

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE Usuarios SET contraseña = %s WHERE usuario_id = %s", (nueva_contraseña_hash, usuario_id))
            conn.commit()

            flash('Contraseña cambiada con éxito', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error al cambiar la contraseña: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('cambiar_contraseña.html')


@app.route('/nueva_contraseña', methods=['GET', 'POST'])
def nueva_contraseña():
    if request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        confirmacion_contraseña = request.form['confirmacion_contraseña']

        if nueva_contraseña != confirmacion_contraseña:
            flash('Las contraseñas no coinciden', 'danger')
            return render_template('nueva_contraseña.html')

        if not validar_contraseña(nueva_contraseña):
            flash('La nueva contraseña no cumple con los requisitos de seguridad', 'danger')
            return render_template('nueva_contraseña.html')

        # Encriptar y actualizar la contraseña
        nueva_contraseña_hash = generate_password_hash(nueva_contraseña)

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE Usuarios SET contraseña = %s WHERE id = %s", (nueva_contraseña_hash, session['usuario_id']))
            conn.commit()

            flash('Contraseña actualizada correctamente', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error al actualizar la contraseña: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('nueva_contraseña.html')

# Función para generar códigos de verificación aleatorios
def generar_codigo(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))




########################################################
@app.route('/perfil', methods=['GET', 'POST'])
@login_required  # Este decorador verifica si el usuario está autenticado
def perfil():
    usuario_id = session['usuario_id']
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Obtener información del usuario
        cur.execute("SELECT nombre, correo, telefono, rol_id, comunidad_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
        usuario = cur.fetchone()

        # Obtener la lista de roles
        cur.execute("SELECT rol_id, nombre FROM roles")
        roles = cur.fetchall()

        # Obtener la lista de comunidades
        cur.execute("SELECT comunidad_id, nombre FROM comunidades")
        comunidades = cur.fetchall()

        if request.method == 'POST':
            # Datos enviados para actualizar el perfil
            nombre = request.form['nombre']
            correo = request.form['correo']
            telefono = request.form['telefono']
            rol_id = request.form['rol_id']
            comunidad_id = request.form['comunidad_id']

            # Validaciones básicas
            if not nombre or not correo or not telefono or not rol_id or not comunidad_id:
                flash('Todos los campos son obligatorios.', 'danger')
                return redirect(url_for('perfil'))

            if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
                flash('Correo inválido', 'danger')
                return redirect(url_for('perfil'))

            if not telefono.isdigit():
                flash('El teléfono debe contener solo números', 'danger')
                return redirect(url_for('perfil'))

            # Actualizar datos del usuario en la base de datos
            cur.execute(
                "UPDATE usuarios SET nombre = %s, correo = %s, telefono = %s, rol_id = %s, comunidad_id = %s WHERE usuario_id = %s",
                (nombre, correo, telefono, rol_id, comunidad_id, usuario_id)
            )
            conn.commit()
            flash('Perfil actualizado correctamente', 'success')

    except Exception as e:
        flash(f'Error al cargar el perfil: {str(e)}', 'danger')
        if conn:
            conn.rollback()
    
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    # Renderizar plantilla con datos del usuario, roles y comunidades
    return render_template('perfil.html', usuario=usuario, roles=roles, comunidades=comunidades)


@app.route('/productos', methods=['GET', 'POST'])
def productos():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))  # Redirigir al login si no está autenticado

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener información del usuario
    cur.execute("SELECT nombre, correo, telefono, rol_id, comunidad_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
    usuario = cur.fetchone()

    if not usuario:
        return "Usuario no encontrado", 404

    # Obtener el rol del usuario
    rol_id = usuario[3]
    if rol_id == 1:
        usuario_rol = 'Administrador'
    else:
        usuario_rol = 'Usuario'

    nombre_usuario = usuario[0]

    # Obtener todos los productos
    cur.execute("SELECT producto_id, nombre, precio, descripcion, imagen_url FROM productos")
    productos = cur.fetchall()

    return render_template('productos.html', nombre=nombre_usuario, usuario_rol=usuario_rol, productos=productos)


@app.route('/pedido')
def pedido():
    # Puedes agregar lógica adicional aquí si es necesario
    return render_template('pedido.html')

@app.route('/pago', methods=['GET', 'POST'])
def pago():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Obtener el nombre del usuario de la base de datos
    cur.execute('SELECT nombre FROM usuarios WHERE usuario_id = %s', (usuario_id,))

    usuario = cur.fetchone()

    # Asegúrate de cerrar el cursor y la conexión
    cur.close()
    conn.close()

    if usuario:
        nombre = usuario[0]  # Asumimos que el nombre está en la primera columna
    else:
        nombre = 'Cliente'  # Valor por defecto en caso de que no se encuentre el usuario

    # Pasar el nombre del usuario a la plantilla
    return render_template('pago.html', nombre=nombre)


@app.route('/admin')
def admin():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    # Verificar si el usuario es el administrador específico
    correo_usuario = session.get('correo')
    if correo_usuario != 'dignosebastiangutierrezoropeza@gmail.com':
        return "No tienes permiso para acceder a esta página.", 403

    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener usuarios que son administradores
    cur.execute("SELECT usuario_id, nombre, correo, rol_id FROM usuarios WHERE rol_id = 1")  # rol_id = 1 para administradores
    usuarios = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('admin.html', usuarios=usuarios)


@app.route('/aceptar_admin/<int:usuario_id>', methods=['POST'])
def aceptar_admin(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Cambiar rol_id a 1 para hacer al usuario administrador
    cur.execute("UPDATE usuarios SET rol_id = 1 WHERE usuario_id = %s", (usuario_id,))
    conn.commit()

    cur.close()
    conn.close()

    return redirect(url_for('admin'))

@app.route('/cancelar_admin/<int:usuario_id>', methods=['POST'])
def cancelar_admin(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Aquí podrías eliminar el rol o asignar otro rol, por ejemplo, 2 para usuarios normales
    cur.execute("UPDATE usuarios SET rol_id = 2 WHERE usuario_id = %s", (usuario_id,))  # Suponiendo que 2 es el rol de usuario normal
    conn.commit()

    cur.close()
    conn.close()

    return redirect(url_for('admin'))


@app.route('/agregar_producto', methods=['POST'])
def agregar_producto():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener el rol del usuario
    cur.execute("SELECT rol_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
    rol_id = cur.fetchone()[0]

    # Verificar si el usuario es Administrador
    if rol_id != 1:
        return "No tienes permiso para agregar productos", 403

    # Obtener los datos del formulario
    nombre = request.form['nombre']
    precio = request.form['precio']
    descripcion = request.form['descripcion']
    imagen_url = request.form['imagen_url']

    # Insertar nuevo producto en la base de datos
    cur.execute("INSERT INTO productos (nombre, precio, descripcion, imagen_url) VALUES (%s, %s, %s, %s)",
                (nombre, precio, descripcion, imagen_url))
    conn.commit()

    # Redirigir a la página de productos después de agregar el nuevo producto
    return redirect(url_for('productos'))


@app.route('/eliminar_producto/<int:producto_id>', methods=['POST'])
def eliminar_producto(producto_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener el rol del usuario
    cur.execute("SELECT rol_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
    rol_id = cur.fetchone()[0]

    # Verificar si el usuario es Administrador
    if rol_id != 1:
        return "No tienes permiso para eliminar productos", 403

    # Eliminar el producto de la base de datos
    cur.execute("DELETE FROM productos WHERE producto_id = %s", (producto_id,))
    conn.commit()

    # Redirigir a la página de productos después de eliminar el producto
    return redirect(url_for('productos'))


# Ruta para subir imágenes

UPLOAD_FOLDER = 'static/uploads/'  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Tipos de archivos permitidos

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'imagen1' not in request.files or 'imagen2' not in request.files:
        flash('No se encontraron archivos')
        return redirect(request.url)

    imagen1 = request.files['imagen1']
    imagen2 = request.files['imagen2']

    # Verifica si se permiten los archivos y guarda
    if imagen1 and allowed_file(imagen1.filename):
        filename1 = secure_filename(imagen1.filename)
        imagen1.save(os.path.join(app.config['UPLOAD_FOLDER'], filename1))
    if imagen2 and allowed_file(imagen2.filename):
        filename2 = secure_filename(imagen2.filename)
        imagen2.save(os.path.join(app.config['UPLOAD_FOLDER'], filename2))

    flash('Imágenes subidas con éxito')
    return redirect(url_for('tu_ruta_de_redireccion'))


if __name__ == '__main__':
    app.run(debug=True)
