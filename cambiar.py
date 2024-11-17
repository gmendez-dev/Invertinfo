import bcrypt
import mysql.connector

# Conexión a la base de datos
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="GERDios#1",
    database="mydb"
)
cursor = db.cursor()

def actualizar_contraseña_usuario(idusuario, nueva_contraseña):
    # Hashear la nueva contraseña
    hashed_password = bcrypt.hashpw(nueva_contraseña.encode('utf-8'), bcrypt.gensalt())

    # Actualizar la contraseña en la base de datos para el usuario con idusuario especificado
    query_update = "UPDATE usuario SET password = %s WHERE idusuario = %s"
    cursor.execute(query_update, (hashed_password.decode('utf-8'), idusuario))
    db.commit()

    print(f"Contraseña actualizada correctamente para el usuario con idusuario = {idusuario}")

# Actualizar la contraseña para el usuario con idusuario = 2
actualizar_contraseña_usuario(2, "Genesis22")

# Cerrar la conexión a la base de datos
cursor.close()
db.close()
