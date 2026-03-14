import requests
import argparse
import re

TARGET_FILE = ".target"
FILTERS_FILE = ".filters"
PAYLOADS_FILE = ".payloads"


def getTargetUrl():
    try:
        with open(TARGET_FILE, "r", encoding="UTF-8") as file:
            return file.readline()
    except FileNotFoundError:
        print("target url not found, set target at least one time using argument '-t'")


def saveTargetUrl(url: str):
    with open(TARGET_FILE, "w", encoding="UTF-8") as file:
        file.write(url)
        print(f"[*] New target url set: {url}")


parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', type=str, help="select target url")

parser.add_argument('-v', '--entry-points',
                    action='store_true', help="find entry points")

parser.add_argument('-f', '--filters', action='store_true',
                    help="find filters")

parser.add_argument('-p', '--payloads', action='store_true',
                    help="generate possible payloads")

parser.add_argument('-i', '--inyection', type=str,
                    help="do a manual inyection")

parser.add_argument('-ir', '--inyection-recursive', action='store_true',
                    help="inyect all the payloads from the file '.payloads'")

args = parser.parse_args()

target_url = None

if args.target:
    target_url = args.target
    saveTargetUrl(target_url)
else:
    target_url = getTargetUrl()


""" TO DO
1. Descubrimiento de entradas: deteccion automatica de parametros GET en URL, formularios POST en el HTML y puntos de inyeccion en la ruta (path injection).

 2. Verificacion de reflexion: envio de un texto único por cada entrada detectada y comprobacion de si el valor se refleja en la respuesta.

 3. Verificacion de persistencia (Stored XSS): tras inyectar el texto, realizar al menos una segunda peticion limpia para comprobar si la entrada persiste.

 4. Analisis de contexto: determinar donde se refleja el texto introducido, para adaptar el payload al contexto real.

 5. Deteccion de filtros: identificar caracteres bloqueados/codificados (por ejemplo <, >, comillas) y palabras prohibidas (por ejemplo script, alert, onerror).

 6. Tecnicas de evasion: proponer variantes de payload

s (cambio de mayusculas/minusculas, alternativas de funciones JS como prompt/confirm, etc.) en funcion de los filtros detectados.

 7. Generacion de payloads: construir una lista de posibles payloads segun el contexto y los filtros identificados.

10. Salida de resultados: mostrar de forma clara los parámetros pontencialmente vulnerables, el tipo de XSS y los payload propuestos.
 """
