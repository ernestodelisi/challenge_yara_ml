from fastapi import FastAPI, UploadFile, HTTPException, Form, Depends, status
from fastapi.responses import JSONResponse
from yara import compile as compile_rules
import sqlite3
import logging
from uvicorn import run
from fastapi.security import APIKeyHeader
from decouple import config
import hashlib
import requests


#creo la app de fastapi
app = FastAPI()

#auth
api_key = APIKeyHeader(name="X-API-Key", auto_error=False)

#funciones

#func de auth
def authenticate_user(api_key: str = Depends(api_key)):
    correct_api_key = config("API_KEY")

    if api_key != correct_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key

# log config
logging.basicConfig(
    filename='logfile.log',
    encoding='utf-8',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# sqlite
try:
    with sqlite3.connect("yara_api.db") as connection:
        cursor = connection.cursor()
except sqlite3.Error as e:
    logging.error(f"Error to connect DB: {e}")

def calculate_file_hash(file):
    sha256_hash = hashlib.sha256()
    while chunk := file.read(8192):
        sha256_hash.update(chunk)
    file.seek(0)  # posicion del archivo en 0
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": config('VT_API_KEY')}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    elif response.status_code == 404:
        return {"malicious": 0}
    else:
        raise HTTPException(status_code=500, detail="Error en la verificación con VirusTotal")


# Endpoints
@app.post("/api/rule")
async def add_rule(rule_data: dict, api_key: str = Depends(authenticate_user)):

    """
    Este Endpoint agrega una nueva regla a la db.

    - Parámetros: rule_data (dict): Datos de la regla que incluyen "name" y "rule_code". api_key (str): API Key para la autenticación.


        **Respuestas:**

    - 201 OK: Status OK y un diccionario con la información de la regla agregada.
    - 400 Bad Request: Parámetros incompletos o incorrectos.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:
        name = rule_data.get("name", "")
        rule_code = rule_data.get("rule_code", "")

        if not name or not rule_code:
            error_message = "name and rule_code are required"
            raise HTTPException(status_code=400, detail=error_message)

        #compilo la regla con compile de yara
        compiled_rule = compile_rules(source=rule_code)

        cursor.execute("""
            INSERT INTO rules (name, rule)
            VALUES (?, ?)
        """, (name, rule_code))

        #confirmamos los cambios realizados en la db
        connection.commit()

        # obtenemos el ultimo ID
        rule_id = cursor.lastrowid

        return JSONResponse(
            content={
                "id": rule_id,
                "name": name,
                "rule": rule_code,
            },
            status_code=201,
        )

    except Exception as e:
        error_message = f"Error adding new rule: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)

@app.post("/api/analyze/text")
async def analyze_text(text_data: dict, username: str = Depends(authenticate_user)):
    """
    Endpoint para analizar un texto con reglas Yara específicas.

    - Parámetros: text_data (dict): Datos del texto que incluyen "text" y "rules". api_key (str): API Key para la autenticación.

        **Respuestas:**

    - 200 OK: Status OK y diccionario con el estado y los resultados del análisis.
    - 400 Bad Request: Parámetros incompletos o incorrectos.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:
        text = text_data.get("text", "")
        rules = text_data.get("rules", [])

        if not text or not rules:
            error_message = "text and rule or rules are required"
            raise HTTPException(status_code=400, detail=error_message)

        # listado de reglas
        rule_ids = [rule.get("rule_id") for rule in rules]

        # buscamos y compilamos las reglas seleccionadas en la db
        compiled_rules_list = [compile_rules(source=cursor.execute("SELECT rule FROM rules WHERE id=?", (rule_id,)).fetchone()[0]) for rule_id in rule_ids]

        # analizamos el texto con las reglas ya compiladas
        matches = [rule.match(data=text) for rule in compiled_rules_list]

        # creamos una lista vacia
        results = []

        for i in range(len(rule_ids)):
            rule_id = rule_ids[i]
            match_list = matches[i]

            # verificamos si hay al menos una coincidencia en match_list
            matched = any(match_list)

            # agregamos un diccionario a la lista results con la información de la coincidencia
            result_dict = {"rule_id": rule_id, "matched": matched}
            results.append(result_dict)

        return {"status": "ok", "results": results}

    except Exception as e:
        error_message = f"Error analyzing text: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)


@app.post("/api/analyze/file")
async def analyze_file(archivo: UploadFile, rules: str = Form(...), api_key: str = Depends(authenticate_user)):
    """
    Endpoint para analizar un archivo en base a una lista de reglas de la db. Este es analizado previamente con VirusTotal.

    - Parámetros:
        - archivo (UploadFile): El archivo a analizar.
        - rules (str): Cadena de texto que contiene las reglas separadas por comas.
        - api_key (str): API Key para la autenticación.

        **Respuestas:**

    - 200 OK: Status OK y resultados del analisis.
        ej: {"status":"ok","results":[{"rule_id":1,"matched":true},{"rule_id":2,"matched":false}]}
    - 400 Bad Request: Parámetros incompletos o incorrectos.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:

        if not archivo or not rules:
            error_message = "archivo and rules are required"
            raise HTTPException(status_code=400, detail=error_message)

        # texto en lista
        rules_list = rules.split(',')
        #convertimos cada elemento de la lista a entero..
        rule_ids = []
        for rule_id_str in rules_list:
            rule_ids.append(int(rule_id_str))

        #calculo el hash del archivo
        archivo_hash = calculate_file_hash(archivo.file)
        #test hash malicioso...
        #archivo_hash = '500d4fc5fa4a192033151be25ee84f1089868990eb4e2fe8680030cc7d415bab'

        logging.info(archivo_hash)

        vt_results = check_virustotal(archivo_hash)
        malicious_count = vt_results.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        #verificamos las detecciones
        if malicious_count > 0:
            raise HTTPException(status_code=500, detail=f"Archivo marcado como malicioso. Cantidad de detecciones maliciosas: {malicious_count}")

        content = archivo.file.read().decode('utf-8')
        archivo.file.seek(0) #vuelve al principio del archivo

        #creamos una lista de las reglas compiladas
        compiled_rules_list = [compile_rules(source=cursor.execute("SELECT rule FROM rules WHERE id=?", (rule_id,)).fetchone()[0]) for rule_id in rule_ids]

        # analizamos el contenido con las reglas compiladas
        matches = [rule.match(data=archivo.file.read()) for rule in compiled_rules_list]

        #creamos una lista para almacenar los resultados
        results = []

        for i in range(len(rule_ids)):
            rule_id = rule_ids[i]
            match_list = matches[i]

            # verificamos si hay al menos una coincidencia en match_list
            matched = any(match_list)

            # agregamos un diccionario a la lista results con la información de la coincidencia
            result_dict = {"rule_id": rule_id, "matched": matched}
            results.append(result_dict)

        return {"status": "ok", "results": results}

    except Exception as e:
        error_message=f"Error analyzing file: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)


# Endpoints adicionales
@app.get("/api/list_rules")
async def get_all_rules(username: str = Depends(authenticate_user)):
    """
    Endpoint para traer todas las reglas de la db.

    - Parámetros:
        - api_key (str): API Key para la autenticación.


    **Respuestas:**

    - 200 OK: Devuelve todas las reglas almacenadas en la db.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:
        cursor.execute("SELECT id, name, rule FROM rules")
        rules = [{"id": row[0], "name": row[1], "rule": row[2]} for row in cursor.fetchall()]
        return rules
    except Exception as e:
        error_message = f"Error getting rules: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)


@app.delete("/api/rule/{rule_id}")
async def delete_rule(rule_id: int, username: str = Depends(authenticate_user)):
    """
    En base a un rule_id, lo elimina de la db.

    - Parámetros:
        - rule_id (int): ID de la regla a eliminar.
        - api_key (str): API Key para la autenticación.

    **Respuestas:**

    - 200 OK: Status OK.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:

        if not rule_id:
            error_message = "rule id are required"
            raise HTTPException(status_code=400, detail=error_message)

        cursor.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        connection.commit()
        return {"status": "ok", "message": "Rule deleted successfully"}
    except Exception as e:
        error_message = f"Error deleting rule: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)



@app.put("/api/rule/{rule_id}")
async def update_rule(rule_id: int, rule_data: dict, username: str = Depends(authenticate_user)):
    """
    En base a un rule_id, se ingresa name y rule_code a ser modificados.

    - Parámetros:
        - rule_id (int): ID de la regla a modificar.
        - rule_data (dict): Datos de la regla que incluyen "name" y "rule_code"
        - api_key (str): API Key para la autenticación.

    **Respuestas:**

    - 200 OK: Status OK.
    - 400 Bad Request: Parámetros incompletos o incorrectos.
    - 401 Unauthorized: API Key Invalida.
    - 500 Internal Server Error: Error del servidor.
    """

    try:
        name = rule_data.get("name", "")
        rule_code = rule_data.get("rule_code", "")

        if not name or not rule_code:
            error_message = "name and rule are required"
            logging.error(error_message)
            raise HTTPException(status_code=400, detail=error_message)

        cursor.execute("UPDATE rules SET name=?, rule=? WHERE id=?", (name, rule_code, rule_id))
        connection.commit()

        return {"status": "ok", "message": "Rule updated successfully"}

    except Exception as e:
        error_message = f"Error updating rule: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=500, detail=error_message)


if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8000, log_config="logging_config.ini")

