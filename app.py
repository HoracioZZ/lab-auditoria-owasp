import os
import psycopg2
from flask import Flask, request, jsonify, make_response
from markupsafe import escape

app = Flask(__name__)

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        user=os.getenv("DB_USER", "devuser"),
        password=os.getenv("DB_PASSWORD", "devpassword123"),
        dbname=os.getenv("DB_NAME", "banco_dev")
    )

# 1. Endpoint Mitigado contra SQLi y XSS Reflejado
@app.route('/api/socios/buscar', methods=['GET'])
def buscar_socio():
    termino = request.args.get('q', '')
    conn = get_connection()
    cur = conn.cursor()
    # MITIGACIÓN SQLi: Uso de consulta parametrizada nativa con ILIKE y tupla
    query = "SELECT id, username, nombre_completo, saldo FROM usuarios WHERE nombre_completo ILIKE %s;"
    try:
        cur.execute(query, (f"%{termino}%",))
        filas = cur.fetchall()
        cur.close()
        conn.close()
        resultados = [{"id": f[0], "username": f[1], "nombre": f[2], "saldo": float(f[3])} for f in filas]
        
        # MITIGACIÓN XSS Reflejado: Sanitización de la entrada mediante escape de Markupsafe
        termino_seguro = escape(termino)
        mensaje = f"<p>Resultados obtenidos para el criterio: {termino_seguro}</p>"
        return make_response(jsonify({"filtro": mensaje, "data": resultados}), 200)
    except Exception as e:
        return jsonify({"error_tecnico": "Error interno procesando la solicitud"}), 500

# 2. Endpoint Mitigado contra BOLA / IDOR
@app.route('/api/socios/<int:usuario_id>/perfil', methods=['GET'])
def ver_perfil(usuario_id):
    # MITIGACIÓN BOLA: Verificación de control de acceso basada en cabecera simulada
    user_id_header = request.headers.get('X-User-Id')
    user_role = request.headers.get('X-User-Role', 'cliente')
    
    # Si no es admin y el ID solicitado no coincide con el autenticado en la cabecera
    if user_role != 'admin' and user_id_header and int(user_id_header) != usuario_id:
        return jsonify({"mensaje": "Acceso denegado: No autorizado para ver este perfil"}), 403

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, nombre_completo, ci, saldo, rol FROM usuarios WHERE id = %s;", (usuario_id,))
    u = cur.fetchone()
    cur.close()
    conn.close()
    if not u:
        return jsonify({"mensaje": "Usuario no encontrado"}), 404
    return jsonify({
        "id": u[0],
        "username": u[1],
        "nombre": u[2],
        "ci": u[3],
        "saldo": float(u[4]),
        "rol": u[5]
    }), 200

# 3. Endpoint Mitigado contra XSS Almacenado
@app.route('/api/comentarios', methods=['GET', 'POST'])
def comentarios():
    conn = get_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        autor = escape(data.get('autor', 'Anonimo'))
        mensaje = escape(data.get('mensaje', '')) # MITIGACIÓN XSS Almacenado
        cur.execute("INSERT INTO comentarios (autor, mensaje) VALUES (%s, %s);", (autor, mensaje))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "comentario registrado"}), 201
    else:
        cur.execute("SELECT autor, mensaje FROM comentarios ORDER BY id DESC;")
        items = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify([{"autor": i[0], "mensaje": i[1]} for i in items]), 200

# 4. Cabeceras Defensivas y Eliminación de Fugas de Servidor
@app.after_request
def aplicar_cabeceras(response):
    # Se eliminan o enmascaran las fugas de versión y se añaden cabeceras de seguridad estrictas
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Se remueven cabeceras por defecto que revelan tecnología
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response

if __name__ == '__main__':
    # MITIGACIÓN: Desactivar debug en producción
    app.run(host='0.0.0.0', port=5000, debug=False)
