import os
import re
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv('.env')
VT_KEY = os.getenv('VT_API_KEY')

def get_file_hash(file_path):
    """Calcula el hash SHA-256 de un archivo local."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    
def extract_hash_from_text(text):
    """Busca cadenas de caracteres que parezcan un hash (MD5, SHA1, SHA256) en un texto."""
    # Buscamos cadenas de 32, 40 o 64 caracteres hexadecimales
    match = re.search(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
    if match:
        return match.group(0)
    return None

def check_hash_vt(file_hash):
    """Consulta a VirusTotal y devuelve un diccionario con los datos crudos."""
    if not VT_KEY:
        return {"error": "Falta la clave de API de VirusTotal."}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attrs = data['data']['attributes']
            stats = attrs['last_analysis_stats']

            # Devolvemos los datos estructurados para que el LLM los entienda
            return {
                "found": True,
                "hash": file_hash,
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "undetected": stats['undetected'],
                "reputation": attrs.get('reputation', 0),
                "tags": attrs.get('tags', []),
                "names": attrs.get('names', [])[:5],  # Solo los primeros 5 nombres
            }
    
        elif response.status_code == 404:
            return {"found": False, "hash": file_hash, "msg": "No encontrado en VirusTotal."}
        else:
            return {"error": f"Error en la consulta a VirusTotal: {response.status_code}"}
    
    except Exception as e:
        return {"error": f"Error al conectar con VirusTotal: {str(e)}"}