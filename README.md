### The Yara API Challenge Documentation

Yara API Challenge es un proyecto de seguridad informática que te permite buscar patrones en textos y binarios utilizando reglas Yara. 
Esta documentación te servira de ayuda para poder desplegar la app usando Docker. 

Para el desarrollo de la API utilice FastAPI. El cual provee muchas ventajas como por ejemplo, validaciones automaticas de los datos de E/S (ej:inyecciones SQL), documentacion automatica, facilidad de uso y un excelente rendimiento.


###Desplegar la aplicacion

Una vez clonado el repositorio de GitHub, debemos seguir los pasos que se describen a continuacion:

#####Construir la imagen de docker

`$ docker-compose build
`
#####Ejecutar la aplicacion

`$ docker-compose up
`
#####Uvicorn comenzara a correr en http://localhost:8000/ 

- Para ver la documentacion generada automaticamente podemos ingresar a:
http://localhost:8000/docs o http://localhost:8000/redoc 

- API KEY: Podemos buscarla dentro del contenedor en el archivo .env.

###Curls de ejemplo

#####Agregar nueva regla

```bash
curl -X POST "http://127.0.0.1:8000/api/rule" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: api-key" \
  -d '{
    "name": "Regla01",
    "rule_code": "rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n $my_text_string\r\n}"
  }'
```

#####Credit Card Rule

```bash
curl -X POST "http://127.0.0.1:8000/api/rule" \
-H "Content-Type: application/json" \
-H "X-API-Key: api-key" \
-d '{
  "name": "CreditCardRule",
  "rule_code": "rule CreditCardRule\n{\n strings:\n   $credit_card = /[0-9]{13,16}/\n condition:\n   $credit_card\n}"
}'
```

#####Tokens

```bash
curl -X POST "http://127.0.0.1:8000/api/rule" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: api-key" \
  -d '{
    "name": "TokenRule",
    "rule_code": "rule TokenRule\r\n{\r\n strings:\r\n $token = /TOKEN_\\d{4}-\\d{2}-\\d{2}_\\d+/ \r\n condition:\r\n $token\r\n}"
  }'
```

#####Tokens after 2016

```bash
curl -X POST "http://127.0.0.1:8000/api/rule" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: api-key" \
  -d '{
    "name": "TokenAfter2016Rule",
    "rule_code": "rule TokenAfter2016Rule\r\n{\r\n strings:\r\n $token = /TOKEN_(201[6-9]|20[2-9][0-9])-([0-1][0-9])-([0-3][0-9])_\\d{6}/ \r\n condition:\r\n $token\r\n}"
  }'
```


#####Analizar texto:

```bash
curl -X 'POST' \
  'http://localhost:8000/api/analyze/text' \
  -H "X-API-Key: api-key" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "text":"esto no es coca papi",
    "rules":
            [
                    {"rule_id": 1},
                    {"rule_id": 2}
            ]
}'
```

#####Analizar Archivo

Como el archivo de ejemplo "toanalize.txt" se encuentra dentro del contenedor, podemos ejecutar el curl de la siguiente manera:
######Informacion sobre los contenedores en ejecucion:
`$ docker ps
`
######Ejecutamos una shell dentro del contenedor yaraapi-web-1
`$ docker exec -it <nombre_del_contenedor> /bin/bash
`
Una vez dentro del contenedor podemos ejecutar el siguiente curl de ejemplo.
Curl ya se encuentra instalado.

```bash
curl -X POST \
  http://localhost:8000/api/analyze/file \
  -H "X-API-Key: api-key" \
  -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
  -F archivo=@toanalize.txt \
  -F 'rules=1,2'
```

#####Listar reglas
```bash
  curl -X GET http://localhost:8000/api/list_rules \
  -H "X-API-Key: api-key" 
```

#####Eliminar regla por ID
```bash
curl -X DELETE http://localhost:8000/api/rule/1 \
  -H "X-API-Key: api-key"
```

#####Modificar nombre y regla por ID
```bash
curl -X PUT http://localhost:8000/api/rule/1 \
-H "X-API-Key: api-key" \
-H 'Content-Type: application/json' \
-d '{"name": "Nueva Regla","rule_code":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n $my_text_string\r\n}"}'
```







# The Yara API Challenge

Como equipo de **seguridad informática** tenemos la necesidad de buscar en textos y binarios algunos patrones que pueden ir desde información sensible hasta malware. Para eso necesitamos integrar **[Yara](http://virustotal.github.io/yara/)** con una **API** que nos permita manejar reglas y analizar estos archivos o textos en busca de estos patrones.
Es importante que como esta API va a tener bastante trafico, no tenga que cargar las reglas cada vez que tenga que hacer un análisis.
Se puede implementar con el lenguaje de programación que prefieras, frameworks y librerias que creas necesarios pero si es importante usar [Docker](https://www.docker.com/) para que sea reproducible facilmente y podamos probarlo.
El challenge consta de una implementación básica y dos optativas y algunos extras.


## Implementación básica

La API deberá contar con tres métodos (Endpoints) que deben cumplir con este contrato

### Add rule
Metodo: `POST`
Path: `/api/rule`
Body:

    {
	    "name":"esto no es coca papi rule",
	    "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n $my_text_string\r\n}"
    }

Response Code: `201` en caso de éxito y en caso de error un status code correspondiente al tipo de error

Response Body:

    {
	    "id": 1,
	    "name": "esto no es coca papi rule",
	    "rule": "rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n $my_text_string\r\n}"
    }
   
Curl de ejemplo:
   
    curl --request POST \
      --url http://localhost:8080/api/rule \
      --header 'content-type: application/json' \
      --data '{
      "name":"esto no es coca papi rule",
      "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"
      }'

  ### Analyze text
Metodo: `POST`
Path: `/api/analyze/text`
Body:

    {
	    "text":"esto es un texto a analizar",
	    "rules": 
		    [
			    {"rule_id": 1},
			    {"rule_id": 2}
		    ]
    }
 Response Code: `200` en caso de éxito y en caso de error un status code correspondiente al tipo de error
 Response Body:

    {
		"status": "ok",
		"results": [
			{
				"rule_id": 1,
				"matched": true
			},
			{
				"rule_id": 2,
				"matched": false
		    }
		]
	}

   Curl de ejemplo:   

    curl --request POST \
      --url http://localhost:8080/api/analyze/text \
      --header 'content-type: application/json' \
      --data '{
    	“text”: ”estoesuntextoaanalizar”,
    	"rules": [
    		{
    			"rule_id": 1
    		},
    		{
    			"rule_id": 2
    		}
    	]
    }'

### Analyze file
Metodo: `POST`
Path: `/api/analyze/file`
Body:  

    multipart/form-data
    rules=1,2
    file=archivo.txt

 Response Code: `200` en caso de éxito y en caso de error un status code correspondiente al tipo de error
 Response Body:

    {
		"status": "ok",
		"results": [
			{
				"rule_id": 1,
				"matched": true
			},
			{
				"rule_id": 2,
				"matched": false
			}
		]
	}

Curl de ejemplo:

    curl -X POST \
      http://localhost:8080/api/analyze/file \
      -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
      -F file=@file \
      -F 'rules=1,2'

## Implementación optativa 1
Sumar al `POST`, un `PUT` y `GET` de reglas con persistencia en una base de datos para hacer un ABM completo de reglas de Yara.
Persistir en esta base de datos, los resultados de los textos y archivos analizados.

## Implementación optativa 2
- Crear una regla Yara que permita encontrar tarjetas de crédito
- Crear una regla Yara que permita encontrar `access_token` con el siguiente formato

        token de ejemplo: TOKEN_2014-06-03_112332
        2014-06-03: fecha de creacion del token en formato año-mes-dia
        112332: id de usuario

- Crear una regla Yara que permita encontrar `access_token` que hayan sido creados después del 31 de enero de 2016

## Extras
- Logging
- Agregar tests
- Documentación
- Autenticación en la api
- Sumar funcionalidades (ejemplo: dada una url, bajar el contenido y analizarlo con reglas yara)

**Recordá que cuanto mas fácil sea de reproducir y podamos ver todo lo que hiciste, mejor :D**

