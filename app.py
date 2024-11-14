from flask import Flask;
from flask import render_template, redirect, request, Response, session, jsonify, url_for, flash;
from flask_mysqldb import MySQL, MySQLdb;
import pandas as pd
import numpy as np
import requests
from sklearn.svm import SVR
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime
import bcrypt

app = Flask(__name__,template_folder='template')
prediccion_data = None

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='GERDios#1'
app.config['MYSQL_DB']='mydb'
app.config['MYSQL_CURSORCLASS']='DictCursor'

API_KEY = 'G5be0vtfR94ws10uA1MsC8f3zBJwbNZE'

mysql=MySQL(app)

#rutas
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def index():
   return render_template('login.html')

@app.route('/admin1')
def admin1():
   return render_template('admin1.html')

@app.route('/user1')
def user1():
   return render_template('user1.html')

@app.route('/buscare')
def buscare():
   return render_template('buscarE.html')

@app.route('/registro')
def registro():
   return render_template('registro.html')

@app.route('/listar_usuarios')
def listar_usuarios():
   return render_template('listar_usuarios.html')

@app.route('/curiosidades')
def curiosidades():
   return render_template('curiosidades.html')

@app.route('/di')
def di():
   return render_template('DI.html')

@app.route('/registro_admin')
def registro_admin():
   return render_template('registro_admin.html')

@app.route('/editar_empres')
def editar_empres():
   return render_template('editar_empresa.html')

@app.route('/qs')
def qs():
   return render_template('QS.html')

@app.route('/todas_empresas')
def todas_empresas():
   return render_template('Todasempresas.html')

@app.route('/todas_empresas1')
def todas_empresas1():
   return render_template('Todasempresas1.html')

@app.route('/prediccion')
def prediccion():
   return render_template('prediccion.html')

@app.route('/proyeccion')
def proyeccion():
   return render_template('proyeccion.html')

@app.route('/historial')
def historial():
   return render_template('historial.html')

@app.route('/proyeccion_usuario')
def proyeccion_usuario():
   return render_template('proyeccion_usuario.html')

@app.route('/buscarE_usuario')
def BuscarE_usuario():
   return render_template('buscarE_usuario.html')

@app.route('/eliminar_cuenta')
def eliminar_cuenta():
   return render_template('eliminar_cuenta.html')

@app.route('/editar_usuario', methods=['GET', 'POST'])
def editar_usuario():
    # Verificar si el usuario está logueado y si tiene un ID de usuario en la sesión
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))  # Redirigir a la página de inicio si no está logueado

    # Verificar si el usuario tiene el rol adecuado (si tienes roles de usuario)
    # Si el rol no es adecuado, redirigirlo a otra página o mostrar un mensaje
    # Por ejemplo, si solo el usuario puede editar su propia cuenta
    if session['idusuario'] != request.args.get('idusuario'):
        flash("No tienes permiso para editar este perfil.", "error")
        return redirect(url_for('home'))  # O redirigir a otra página de acceso autorizado

    idusuario = session['idusuario']
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM usuario WHERE idusuario=%s', (idusuario,))
    usuarios = cur.fetchone()
    cur.close()
    
    # Verifica si el usuario existe
    if not usuarios:
        flash("No se encontraron datos del usuario.", "error")
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Obtener los datos del formulario
        nombre = request.form['txtnombre']
        username = request.form['txtusername']
        correo = request.form['txtcorreo']
        password = request.form['txtpassword']  # Nueva contraseña (si se proporciona)
        telefono = request.form['txttelefono']
        direccion = request.form['txtdireccion']
        tipo_empresa = request.form['tipo_empresa']
        
        # Si se ingresa una nueva contraseña, encriptarla con bcrypt
        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            password = hashed_password.decode('utf-8')  # Guardar la contraseña encriptada
        else:
            # Si no se ingresa una nueva contraseña, conservar la anterior
            password = usuarios['password']

        # Actualizar la información del usuario en la base de datos
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE usuario 
            SET nombre = %s, username = %s, correo = %s, password = %s, telefono = %s, Direccion = %s, Interes = %s
            WHERE idusuario = %s
        """, (nombre, username, correo, password, telefono, direccion, tipo_empresa, idusuario))
        mysql.connection.commit()
        cur.close()

        flash("Datos actualizados correctamente.", "success")
        return redirect(url_for('editar_usuario'))

    return render_template('editar_usuario.html', usuarios=usuarios)


@app.route('/crud_empresas')
def crud_empresas():
    # Verificar si el usuario está logueado
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    # validacion solo administrador puede acceder a:
    if session['tipo_usuario_idtipo_usuario'] != 1: 
        flash("No tienes permiso para acceder a esta página.", "error")
        return redirect(url_for('home'))
    
    # Consulta para obtener las empresas
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa')
    empresa = cur.fetchall()
    cur.close()

    # Log de las empresas (puedes eliminar este print en producción)
    print(empresa)

    return render_template('crud_empresas.html', empresa=empresa)

@app.route('/edit_us', methods=['POST'])
def edit_us():
    # Verificar si el usuario está logueado
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    idusuario = session['idusuario']  # Obtener el ID del usuario desde la sesión

    # Obtener los valores del formulario
    nombre = request.form['txtnombre']
    username = request.form['txtusername']
    correo = request.form['txtcorreo']
    password = request.form['txtpassword']
    telefono = request.form['txttelefono']
    direccion = request.form['txtdireccion']
    tipo_empresa = request.form['tipo_empresa']

    # Conectar a la base de datos
    cur = mysql.connection.cursor()

    # Verificar que el usuario que está editando los datos es el dueño de la cuenta
    cur.execute("SELECT idusuario FROM usuario WHERE idusuario = %s", (idusuario,))
    usuario_en_db = cur.fetchone()

    if not usuario_en_db:
        flash("No se encontraron datos del usuario. Acceso no autorizado.", "error")
        return redirect(url_for('home'))

    # Obtener el interés actual del usuario
    cur.execute("SELECT Interes FROM usuario WHERE idusuario = %s", (idusuario,))
    interes_actual = cur.fetchone()
    interes = tipo_empresa if tipo_empresa else interes_actual['Interes']  # Mantener el interés actual si no se envía uno nuevo

    # Si se ha ingresado una nueva contraseña, encriptarla
    if password:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        password = hashed_password.decode('utf-8')  # Guardar la contraseña encriptada
    else:
        # Si no se ingresa una nueva contraseña, conservar la anterior
        cur.execute("SELECT password FROM usuario WHERE idusuario = %s", (idusuario,))
        password = cur.fetchone()['password']

    # Actualizar los datos del usuario en la base de datos
    cur.execute("""
        UPDATE usuario 
        SET nombre = %s, username = %s, correo = %s, password = %s, telefono = %s, Direccion = %s, Interes = %s
        WHERE idusuario = %s
    """, (nombre, username, correo, password, telefono, direccion, interes, idusuario))

    # Confirmar la actualización
    mysql.connection.commit()
    cur.close()

    flash("Datos actualizados correctamente.", "success")
    return render_template('user1.html')


@app.route('/eliminar_c', methods=["GET", "POST"])
def eliminar_c():
    # Asegurarse de que el usuario ha iniciado sesión
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    idusuario = session['idusuario']  # Obtener el ID del usuario desde la sesión
    cur = mysql.connection.cursor()

    try:
        # Ejecuta la consulta con el marcador de posición para eliminar el usuario
        cur.execute('DELETE FROM usuario WHERE idusuario = %s', (idusuario,))
        mysql.connection.commit()
        flash("Tu cuenta ha sido eliminada exitosamente.", "success")
        # Eliminar la sesión después de la eliminación de la cuenta
        session.pop('idusuario', None)
    except Exception as e:
        flash("Ocurrió un error al intentar eliminar la cuenta.", "error")
        return str(e), 500
    finally:
        cur.close()

    return redirect(url_for('home'))


@app.route('/acceso-login', methods=["GET", "POST"])
def login():
    if request.method == 'POST' and 'txtcorreo' in request.form and 'txtpassword' in request.form:
        _correo = request.form['txtcorreo']
        _password = request.form['txtpassword']

        # Establecer conexión con la base de datos
        cur = mysql.connection.cursor()

        # Consultar el correo y la contraseña encriptada desde la base de datos
        cur.execute('SELECT idusuario, password, tipo_usuario_idtipo_usuario, nombre FROM usuario WHERE correo = %s', (_correo,))
        account = cur.fetchone()

        if account:
            # Recuperar la contraseña encriptada almacenada en la base de datos
            contraseña_encriptada = account['password']
            
            # Verificar si la contraseña ingresada coincide con la encriptada
            if bcrypt.checkpw(_password.encode('utf-8'), contraseña_encriptada.encode('utf-8')):
                # Si las contraseñas coinciden, almacenar información en la sesión
                session['logueado'] = True
                session['idusuario'] = account['idusuario']
                session['tipo_usuario_idtipo_usuario'] = account['tipo_usuario_idtipo_usuario']
                session['nombre_usuario'] = account['nombre']

                # Redirigir al tipo de usuario correspondiente
                if session['tipo_usuario_idtipo_usuario'] == 1:
                    return render_template("admin1.html")
                elif session['tipo_usuario_idtipo_usuario'] == 2:
                    return render_template("user1.html")
            else:
                # Si las contraseñas no coinciden
                return render_template('login.html', mensaje="Usuario y/o contraseña Incorrectos")
        else:
            # Si el usuario no existe
            return render_template('login.html', mensaje="Usuario y/o contraseña Incorrectos")
    
    return render_template('login.html')

#Funcion Registro
@app.route('/crear-registro', methods=["GET", "POST"])
def crear_registro():
    # Verificar si el usuario está logueado
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    # Si es un POST, procesamos los datos del formulario
    if request.method == "POST":
        nombre = request.form['txtnombre']
        usuario = request.form['txtusuario']
        correo = request.form['txtcorreo']
        password = request.form['txtpassword']
        telefono = request.form['txttelefono']
        direccion = request.form['txtdireccion']
        preferencia = request.form['tipo_empresa']

        # Validación de usuario existente (correo o nombre de usuario)
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM usuario WHERE correo = %s OR username = %s", (correo, usuario))
        usuario_existente = cur.fetchone()

        if usuario_existente:
            flash("El correo o el nombre de usuario ya está registrado. Por favor, elige otro.", "error")
            return render_template('crear_registro.html')

        # Encriptar la contraseña con bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insertar los datos del nuevo usuario
        cur.execute("""
            INSERT INTO usuario (nombre, username, correo, password, fecha_registro, tipo_usuario_idtipo_usuario, telefono, Direccion, Interes)
            VALUES (%s, %s, %s, %s, NOW(), '2', %s, %s, %s)
        """, (nombre, usuario, correo, hashed_password.decode('utf-8'), telefono, direccion, preferencia))
        mysql.connection.commit()
        cur.close()

        flash("Usuario creado correctamente. Por favor, inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('crear_registro.html')

#Funcion registro empresa
@app.route('/agregar_empresas', methods=["GET", "POST"])
def agregar_empresas():
    # Verificar si el usuario está logueado
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))
    
    idusuario = session['idusuario']
    cur = mysql.connection.cursor()
    cur.execute("SELECT tipo_usuario_idtipo_usuario FROM usuario WHERE idusuario = %s", (idusuario,))
    usuario = cur.fetchone()

    if not usuario or usuario['tipo_usuario_idtipo_usuario'] != 1:  # 1 es el ID del administrador
        flash("No tienes permisos para acceder a esta página.", "error")
        return redirect(url_for('home'))
    
    # Si es un POST, procesamos los datos del formulario
    if request.method == "POST":
        nombre_corporativo = request.form['txtnombreC']
        nombre_comercial = request.form['txtnombreCo']
        bolsa = request.form['txtbolsa']
        simbolo = request.form['txtsimbolo']
        tipoempresa = request.form['txttipo']
        
        # Insertar los datos de la nueva empresa
        cur.execute("""
            INSERT INTO empresa (nombre_empresa, nombre_comercial, BolsaV, Simbolo, tipo_empresa_idtipo_empresa)
            VALUES (%s, %s, %s, %s, %s)
        """, (nombre_corporativo, nombre_comercial, bolsa, simbolo, tipoempresa))
        mysql.connection.commit()
        cur.close()

        flash("Empresa agregada correctamente.", "success")
        return redirect(url_for('crud_empresas'))

    return render_template('agregar_empresas.html')


#Funcion Registro_administrador
@app.route('/crear-registro-admin', methods=["GET","POST"])
def crear_registro_admin():

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    nombre=request.form['txtnombre']
    usuario=request.form['txtusuario']
    correo=request.form['txtcorreo']
    password=request.form['txtpassword']
    telefono=request.form['txttelefono']
    direccion=request.form['txtdireccion']
    preferencia=request.form['tipo_empresa']


    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO usuario (nombre, username, correo, password, fecha_registro, tipo_usuario_idtipo_usuario,telefono, Direccion, Interes) VALUES (%s,%s,%s,%s,NOW(),'1',%s,%s,%s)" ,(nombre,usuario,correo,password,telefono,direccion,preferencia))
    mysql.connection.commit()

    return render_template('admin1.html', mensaje2="Usuario Administrador creado correctamente")

#listar Usuario (Para usuario administrador)
@app.route('/listar', methods=["GET","POST"])
def listar():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM usuario')
    usuario = cur.fetchall()
    cur.close()

    print(usuario)
    return render_template('listar_usuarios.html',usuario=usuario)

#Mostrar datos para editar empresas
@app.route('/editar_empresa/mostrar/<idempresa>')
def editar_empresa_mostrar(idempresa):
    cur =  mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa WHERE idempresa=%s',(idempresa,))
    mysql.connection.commit()
    empresas = cur.fetchone()
    return render_template('editar_empresa.html',empresas=empresas)

@app.route('/editar_empresa/<int:idempresa>', methods=['POST'])
def editar_empresa(idempresa):

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    nombre_corporativo = request.form['txtnombreC']
    nombre_comercial = request.form['txtnombreCo']
    bolsa = request.form['txtbolsa']
    simbolo = request.form['txtsimbolo']
    tipoempresa = request.form['txttipo']

    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE empresa 
        SET nombre_empresa=%s, nombre_comercial=%s, BolsaV=%s, Simbolo=%s, tipo_empresa_idtipo_empresa=%s 
        WHERE idempresa=%s
    """, (nombre_corporativo, nombre_comercial, bolsa, simbolo, tipoempresa, idempresa))
    mysql.connection.commit()
    cur.close()

    return redirect('/crud_empresas')

@app.route('/eliminar_empresa/<int:idempresa>')
def eliminar_empresa(idempresa):
    
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Convierte idempresa a un entero si es necesario
        idempresa = int(idempresa) 

        # Ejecuta la consulta con el marcador de posición
        cur.execute('DELETE FROM empresa WHERE idempresa = %s', (idempresa,))
        mysql.connection.commit()
    except ValueError:
        # Manejo de error si la conversión falla
        return "ID de empresa no válido", 400
    except Exception as e:
        # Manejo de cualquier otro error
        return str(e), 500
    finally:
        cur.close()  # Asegúrate de cerrar el cursor después de usarlo

    return redirect('/crud_empresas')

@app.route('/his_us', methods=['GET','POST'])
def his_us():
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    idusuario = session['idusuario']
    tipo = request.form['tipo_historial']

    # Validar tipo de historial
    if tipo == 'pre':
        return pre(idusuario)
    elif tipo == 'pro':
        return pro(idusuario)
    elif tipo == 'ambos':
        return ambos(idusuario)
    else:
        flash("Tipo de historial no reconocido", "error")
        return redirect(url_for('home'))

def pre(idusuario):
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM prediccion WHERE usuario_idusuario = %s', (idusuario,))
    prediccion = cur.fetchall()  # Recuperar todas las predicciones del usuario
    cur.close()

    if prediccion:
        flash("Se muestran las predicciones", "warning")
    else:
        flash("No se encontraron predicciones para este usuario", "error")

    return render_template('historial.html', prediccion=prediccion)

def pro(idusuario):
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM proyeccion WHERE usuario_idusuario = %s', (idusuario,))
    proyeccion = cur.fetchall()  # Recuperar todas las proyecciones del usuario
    cur.close()

    if proyeccion:
        flash("Se muestran las proyecciones", "warning")
    else:
        flash("No se encontraron proyecciones para este usuario", "error")

    return render_template('historial.html', proyeccion=proyeccion)

def ambos(idusuario):
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM prediccion WHERE usuario_idusuario = %s', (idusuario,))
    pre = cur.fetchall()  # Recuperar todas las predicciones del usuario
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM proyeccion WHERE usuario_idusuario = %s', (idusuario,))
    proy = cur.fetchall()  # Recuperar todas las proyecciones del usuario
    cur.close()

    # Validar si se encontraron datos
    if proy and pre:
        flash("Se muestran las predicciones y proyecciones", "warning")
    else:
        flash("No se encontraron datos para este usuario", "error")

    return render_template('historial.html', proy=proy, pre=pre)

@app.route('/proyeccion_us', methods=['GET','POST'])
def proyeccion_us():

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))
    
    nombre = request.form['txtnombre']
    cantidad = request.form['txtcantidad']
    anios = request.form['txtanios']
    tipo = request.form['tipo_empresa']

    if tipo == 'Empresas_nacionales':
        return proyectar_nacionales1(nombre)
    elif tipo == 'Otras_empresas':
        return proyectar_otras1(nombre, anios, cantidad)
    else:
        return "Tipo de empresa no reconocido"

def proyectar_nacionales1(nombre):
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))
    
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa WHERE nombre_comercial = %s', (nombre,))
    empresa = cur.fetchone()  # Buscamos la empresa por su nombre comercial
    cur.close()
    
    if empresa:
        flash("La empresa que seleccionaste es nacional, con estas empresas no se puede realizar una proyección ya que no se tienen acciones, son bonos y unicamente cotizan en la Bolsa de Valores Nacional adicional el Valor del bono es fijo de Q.10,000.00, pero para poder adquirir dichos bonos se debe gestionar con un corredor registrado en BVN y estos tienen comisiones individuales por gestion las cuales son dificiles y complejas de calcular.", "Warning")
    else:
        flash("Empresa no encontrada", "error")
    
    return render_template('proyeccion_usuario.html')

def proyectar_otras1(nombre, anios, cantidad):

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    global proyeccion_data

    if request.method == 'POST':
        try:
            anios = int(anios)
            cantidad = int(cantidad)
        except ValueError:
            return render_template('proyeccion_usuario.html', mensaje="Los valores de años y cantidad deben ser números enteros")

        # Realizar la consulta al API de FMP para obtener los datos de la empresa
        url = f'https://financialmodelingprep.com/api/v3/quote/{nombre}?apikey={API_KEY}'
        response = requests.get(url)

        if response.status_code != 200:
            return render_template('proyeccion_usuario.html', mensaje="Error en la consulta a la API para la empresa")

        data = response.json()
        if not data or 'symbol' not in data[0]:
            return render_template('proyeccion_usuario.html', mensaje="No se encontraron resultados para esta empresa")

        empresa = data[0]
        simbolo = empresa['symbol']
        nombre_empresa = empresa['name']

        # Obtener los dividendos históricos de la empresa
        url_dividendos = f'https://financialmodelingprep.com/api/v3/historical-price-full/stock_dividend/{simbolo}?apikey={API_KEY}'
        response_dividendos = requests.get(url_dividendos)

        if response_dividendos.status_code != 200:
            return render_template('proyeccion_usuario.html', mensaje="Error al obtener los dividendos de la empresa")

        data_dividendos = response_dividendos.json()
        if 'historical' not in data_dividendos:
            return render_template('proyeccion_usuario.html', mensaje="No se encontraron datos de dividendos para esta empresa")

        # Calcular el promedio de dividendos y crecimiento, con ajuste para proyecciones de 1 año
        dividendos = data_dividendos['historical']
        total_dividendos = 0
        crecimiento_dividendo = 0

        # Calcular promedio y crecimiento solo si es más de 1 año
        if anios > 1:
            for i in range(1, min(anios, len(dividendos))):
                dividendo_actual = dividendos[i]['dividend']
                dividendo_anterior = dividendos[i-1]['dividend']
                crecimiento_dividendo += (dividendo_actual / dividendo_anterior) - 1
                total_dividendos += dividendo_actual
            promedio_dividendo = total_dividendos / min(anios, len(dividendos))
            tasa_crecimiento_promedio = crecimiento_dividendo / max(1, (len(dividendos) - 1))
        else:
            # Para un año, tomar el último dividendo conocido
            promedio_dividendo = dividendos[0]['dividend'] if dividendos else 0
            tasa_crecimiento_promedio = 0

        # Proyectar utilidad con ajuste para un solo año sin crecimiento
        utilidad_proyectada = 0
        for año in range(anios):
            utilidad_proyectada += promedio_dividendo * (1 + tasa_crecimiento_promedio) ** año * cantidad

        proyeccion_data = {
            'fecha': datetime.now().strftime('%Y-%m-%d'),
            'nombre_empresa': nombre_empresa,
            'cantidad_inversion': cantidad,
            'plazo': anios,
            'utilidad': round(utilidad_proyectada, 2),
            'id_usuario': session['idusuario']
        }

        return render_template('proyeccion_usuario.html', pro=proyeccion_data)

    return redirect('proyeccion_usuario')

@app.route('/proyeccion_empresas', methods=['GET','POST'])
def proyeccion_empresa():
    nombre = request.form['txtnombre']
    cantidad = request.form['txtcantidad']
    anios = request.form['txtanios']
    tipo = request.form['tipo_empresa']

    if tipo == 'Empresas_nacionales':
        return proyectar_nacionales(nombre)
    elif tipo == 'Otras_empresas':
        return proyectar_otras(nombre, anios, cantidad)
    else:
        return "Tipo de empresa no reconocido"

def proyectar_nacionales(nombre):
    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))
    
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa WHERE nombre_comercial = %s', (nombre,))
    empresa = cur.fetchone()  # Buscamos la empresa por su nombre comercial
    cur.close()
    
    if empresa:
        flash("La empresa que seleccionaste es nacional, con estas empresas no se puede realizar una proyección ya que no se tienen acciones, son bonos y unicamente cotizan en la Bolsa de Valores Nacional adicional el Valor del bono es fijo de Q.10,000.00, pero para poder adquirir dichos bonos se debe gestionar con un corredor registrado en BVN y estos tienen comisiones individuales por gestion las cuales son dificiles y complejas de calcular.", "Warning")
    else:
        flash("Empresa no encontrada", "error")

    return render_template('proyeccion.html')

def proyectar_otras(nombre, anios, cantidad):

    global proyeccion_data

    if request.method == 'POST':
        try:
            anios = int(anios)
            cantidad = int(cantidad)
        except ValueError:
            return render_template('proyeccion.html', mensaje="Los valores de años y cantidad deben ser números enteros")

        # Realizar la consulta al API de FMP para obtener los datos de la empresa
        url = f'https://financialmodelingprep.com/api/v3/quote/{nombre}?apikey={API_KEY}'
        response = requests.get(url)

        if response.status_code != 200:
            return render_template('proyeccion.html', mensaje="Error en la consulta a la API para la empresa")

        data = response.json()
        if not data or 'symbol' not in data[0]:
            return render_template('proyeccion.html', mensaje="No se encontraron resultados para esta empresa")

        empresa = data[0]
        simbolo = empresa['symbol']
        nombre_empresa = empresa['name']

        # Obtener los dividendos históricos de la empresa
        url_dividendos = f'https://financialmodelingprep.com/api/v3/historical-price-full/stock_dividend/{simbolo}?apikey={API_KEY}'
        response_dividendos = requests.get(url_dividendos)

        if response_dividendos.status_code != 200:
            return render_template('proyeccion.html', mensaje="Error al obtener los dividendos de la empresa")

        data_dividendos = response_dividendos.json()
        if 'historical' not in data_dividendos:
            return render_template('proyeccion.html', mensaje="No se encontraron datos de dividendos para esta empresa")

        # Calcular el promedio de dividendos y crecimiento, con ajuste para proyecciones de 1 año
        dividendos = data_dividendos['historical']
        total_dividendos = 0
        crecimiento_dividendo = 0

        # Calcular promedio y crecimiento solo si es más de 1 año
        if anios > 1:
            for i in range(1, min(anios, len(dividendos))):
                dividendo_actual = dividendos[i]['dividend']
                dividendo_anterior = dividendos[i-1]['dividend']
                crecimiento_dividendo += (dividendo_actual / dividendo_anterior) - 1
                total_dividendos += dividendo_actual
            promedio_dividendo = total_dividendos / min(anios, len(dividendos))
            tasa_crecimiento_promedio = crecimiento_dividendo / max(1, (len(dividendos) - 1))
        else:
            # Para un año, tomar el último dividendo conocido
            promedio_dividendo = dividendos[0]['dividend'] if dividendos else 0
            tasa_crecimiento_promedio = 0

        # Proyectar utilidad con ajuste para un solo año sin crecimiento
        utilidad_proyectada = 0
        for año in range(anios):
            utilidad_proyectada += promedio_dividendo * (1 + tasa_crecimiento_promedio) ** año * cantidad

        proyeccion_data = {
            'fecha': datetime.now().strftime('%Y-%m-%d'),
            'nombre_empresa': nombre_empresa,
            'cantidad_inversion': cantidad,
            'plazo': anios,
            'utilidad': round(utilidad_proyectada, 2),
            'id_usuario': session['idusuario']
        }

        return render_template('proyeccion.html', pro=proyeccion_data)

    return render_template('proyeccion.html')

@app.route('/guardar_proyeccion', methods=['POST'])
def guardar_proyeccion():
    if 'idusuario' not in session:
        return redirect(url_for('home'))
    
    # Verifica que proyeccion_data esté definido y tenga contenido
    if not 'proyeccion_data' in globals() or not proyeccion_data:
        flash("No hay datos en la proyección para guardar.", "danger")
        return redirect(url_for('proyeccion'))

    try:
        # Guardar la proyección en la base de datos
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO proyeccion (fecha, cantidad_inv, plazo, Utilidad, nombre_empresa, usuario_idusuario) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                proyeccion_data['fecha'],
                proyeccion_data['cantidad_inversion'],
                proyeccion_data['plazo'],
                proyeccion_data['utilidad'],
                proyeccion_data['nombre_empresa'],
                proyeccion_data['id_usuario']
            )
        )
        mysql.connection.commit()
        cursor.close()
        flash("Proyección guardada con éxito.", "success")
        return redirect(url_for('proyeccion_usuario'))

    except KeyError as e:
        flash(f"Falta un dato en proyeccion_data: {e}", "danger")
        return redirect(url_for('proyeccion'))
    except Exception as e:
        flash(f"Error al guardar la proyección: {e}", "danger")
        return redirect(url_for('proyeccion'))


@app.route('/buscar_empresa', methods=['GET','POST'])
def buscar_empresa():
    nombre = request.form['txtnombre']
    tipo = request.form['tipo_empresa']


    if tipo == 'Empresas_nacionales':
        return buscar_nacionales(nombre)
    elif tipo == 'Empresas_PEG':
        return buscar_PEG(nombre)
    else:
        return "Tipo de empresa no reconocido"

def buscar_nacionales(nombre):
    cur =  mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa WHERE nombre_comercial=%s',(nombre,))
    empre = cur.fetchall()
    cur.close()
    print(empre)
    return render_template('buscarE.html',empre=empre)

def buscar_PEG(nombre):
    url = f"https://financialmodelingprep.com/api/v3/search?query={nombre}&apikey={API_KEY}"
    response = requests.get(url)

    print("URL solicitada:", url)  # Verifica la URL generada
    
    if response.status_code == 200:
        data = response.json()
        print("Datos recibidos del API:", data)  # Verifica los datos recibidos
        if data:
            empresa = data[0]
            empre = [{
                'nombre_comercial': empresa['name'],
                'BolsaV': empresa['exchangeShortName'],
                'Simbolo': empresa['symbol'],
            }]
            return render_template('buscarE.html', empre=empre)
        else:
            print("No se encontraron empresas con ese nombre en el API.")  # Mensaje de datos vacíos
            return render_template('buscarE.html', empre=None)
    else:
        return "Error al conectar con el API de FinancialModelingPrep", 500
    

@app.route('/buscar_empresa1', methods=['GET','POST'])
def buscar_empresa1():

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    nombre = request.form['txtnombre']
    tipo = request.form['tipo_empresa']


    if tipo == 'Empresas_nacionales':
        return buscar_nacionales1(nombre)
    elif tipo == 'Empresas_PEG':
        return buscar_PEG1(nombre)
    else:
        return "Tipo de empresa no reconocido"

def buscar_nacionales1(nombre):

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    cur =  mysql.connection.cursor()
    cur.execute('SELECT * FROM empresa WHERE nombre_comercial=%s',(nombre,))
    empre = cur.fetchall()
    cur.close()
    print(empre)
    return render_template('buscarE.html',empre=empre)

def buscar_PEG1(nombre):

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    url = f"https://financialmodelingprep.com/api/v3/search?query={nombre}&apikey={API_KEY}"
    response = requests.get(url)

    print("URL solicitada:", url)  # Verifica la URL generada
    
    if response.status_code == 200:
        data = response.json()
        print("Datos recibidos del API:", data)  # Verifica los datos recibidos
        if data:
            empresa = data[0]
            empre = [{
                'nombre_comercial': empresa['name'],
                'BolsaV': empresa['exchangeShortName'],
                'Simbolo': empresa['symbol'],
            }]
            return render_template('buscarE_usuario.html', empre=empre)
        else:
            print("No se encontraron empresas con ese nombre en el API.")  # Mensaje de datos vacíos
            return render_template('buscarE_usuario.html', empre=None)
    else:
        return "Error al conectar con el API de FinancialModelingPrep", 500

@app.route('/listar_Tempresas')
def listar_Tempresas():
    url = f'https://financialmodelingprep.com/api/v3/stock/list?apikey={API_KEY}'
    page = int(request.args.get('page', 1))  # Página actual, por defecto es la página 1
    empresas_por_pagina = 20  # Ahora 20 empresas por página
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Verifica si la solicitud fue exitosa
        empresas = response.json()

        # Filtramos los datos para incluir solo los campos necesarios
        datos_empresas = [
            {
                'nombre': empresa.get('name', 'N/A'),
                'bolsa': empresa.get('exchange', 'N/A'),
                'simbolo': empresa.get('symbol', 'N/A'),
                'tipo': empresa.get('type', 'N/A')
            }
            for empresa in empresas
        ]
        
        # Calculamos el número total de páginas
        total_empresas = len(datos_empresas)
        total_pages = (total_empresas // empresas_por_pagina) + (1 if total_empresas % empresas_por_pagina > 0 else 0)
        
        # Calculamos el índice de inicio y fin para la página actual
        start = (page - 1) * empresas_por_pagina
        end = start + empresas_por_pagina
        empresas_pagina = datos_empresas[start:end]

        # Renderizamos la plantilla HTML con los datos de las empresas y la paginación
        return render_template('/Todasempresas.html', empre=empresas_pagina, page=page, total_pages=total_pages)

    except requests.exceptions.RequestException as e:
        print(f"Error al conectarse a la API: {e}")
        return "Error al obtener los datos de la API. Intente de nuevo más tarde."

@app.route('/listar_Tempresas1')
def listar_Tempresas1():

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))
    
    url = f'https://financialmodelingprep.com/api/v3/stock/list?apikey={API_KEY}'
    page = int(request.args.get('page', 1))  # Página actual, por defecto es la página 1
    empresas_por_pagina = 20  # Ahora 20 empresas por página
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Verifica si la solicitud fue exitosa
        empresas = response.json()

        # Filtramos los datos para incluir solo los campos necesarios
        datos_empresas = [
            {
                'nombre': empresa.get('name', 'N/A'),
                'bolsa': empresa.get('exchange', 'N/A'),
                'simbolo': empresa.get('symbol', 'N/A'),
                'tipo': empresa.get('type', 'N/A')
            }
            for empresa in empresas
        ]
        
        # Calculamos el número total de páginas
        total_empresas = len(datos_empresas)
        total_pages = (total_empresas // empresas_por_pagina) + (1 if total_empresas % empresas_por_pagina > 0 else 0)
        
        # Calculamos el índice de inicio y fin para la página actual
        start = (page - 1) * empresas_por_pagina
        end = start + empresas_por_pagina
        empresas_pagina = datos_empresas[start:end]

        # Renderizamos la plantilla HTML con los datos de las empresas y la paginación
        return render_template('/Todasempresas1.html', empre=empresas_pagina, page=page, total_pages=total_pages)

    except requests.exceptions.RequestException as e:
        print(f"Error al conectarse a la API: {e}")
        return "Error al obtener los datos de la API. Intente de nuevo más tarde."


@app.route('/realizar_prediccion', methods=['POST'])
def realizar_prediccion():
    global prediccion_data  # Utilizamos la variable global

    if 'idusuario' not in session:
        flash("Por favor, inicia sesión para acceder a esta funcionalidad.", "error")
        return redirect(url_for('home'))

    nombre_empresa = request.form['nombreEmpresa']
    
    # Llama al API de FinancialModelingPrep
    url = f"https://financialmodelingprep.com/api/v3/historical-price-full/{nombre_empresa}?apikey={API_KEY}"
    print("URL solicitada:", url)

    try:
        response = requests.get(url)
        response.raise_for_status()

        # Procesa la respuesta JSON
        data = response.json()
        
        # Verifica si la clave 'historical' existe y tiene datos
        historico = data.get('historical', [])
        if not historico:
            flash("No se encontraron datos para la empresa especificada.", "danger")
            return redirect(url_for('prediccion'))  # Regresa a la página de predicción

        # Crea un DataFrame usando los datos históricos
        df = pd.DataFrame(historico)

        if 'close' not in df.columns:
            flash("Datos históricos inválidos o incompletos para la empresa especificada.", "warning")
            return redirect(url_for('prediccion'))

        # Asegurarse de que no haya valores nulos en 'close'
        df = df.dropna(subset=['close'])
        if df.empty:
            flash("No se encontraron suficientes datos válidos para realizar la predicción.", "warning")
            return redirect(url_for('prediccion'))

        # Entrenamiento del modelo SVR
        df['close'] = df['close'].astype(float)
        x = np.array(range(len(df))).reshape(-1, 1)
        y = df['close'].values
        modelo = SVR(kernel='linear')
        modelo.fit(x, y)
        # Predicción del valor futuro (siguiente día)
        valor_predicho = modelo.predict(np.array([[len(df)]]))[0]

        # Obteniendo el valor real del último día
        valor_real = df['close'].iloc[-1]
        # Calcular la diferencia y asegurarse de que sea positiva
        diferencia = abs(valor_real - valor_predicho)

        # Limitar los valores a 2 decimales
        valor_predicho = round(valor_predicho, 2)
        diferencia = round(diferencia, 2)
        valor_real = round(valor_real, 2)

        # Almacenando los datos de predicción en la variable global
        prediccion_data = {
            'fecha': datetime.now().strftime('%Y-%m-%d'),
            'valor_predicho': valor_predicho,
            'valor_real': valor_real,
            'diferencia': diferencia,
            'nombre_empresa': nombre_empresa,
            'id_usuario': session['idusuario']
        }

        flash("Predicción realizada exitosamente.", "success")
        return render_template('prediccion.html', datas=prediccion_data)
    
    except requests.exceptions.HTTPError as http_err:
        flash("Error al obtener datos de la API. Verifica el nombre de la empresa y la API key.", "info")
    except Exception as err:
        flash("Error en la solicitud o el procesamiento de datos.", "danger")

    return redirect(url_for('prediccion'))

@app.route('/guardar_prediccion', methods=['POST'])
def guardar_prediccion():
    if 'idusuario' not in session:
        return redirect(url_for('home'))
    
    if not prediccion_data:
        flash("No hay datos en la prediccion para guardar.", "danger")

    # Guardar la predicción en la base de datos
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO prediccion (fecha, valor_predicho, valor_real, dif_por, usuario_idusuario, nombre_empresa) VALUES (%s, %s, %s, %s, %s, %s)", 
                   (prediccion_data['fecha'], prediccion_data['valor_predicho'], prediccion_data['valor_real'], prediccion_data['diferencia'], prediccion_data['id_usuario'], prediccion_data['nombre_empresa']))
    mysql.connection.commit()
    cursor.close()
    flash("Prediccion guardada con Exito.", "success")
    return redirect(url_for('prediccion'))


if __name__ == '__main__':
    app.secret_key="Pr0y3ct0F1n4l"
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)