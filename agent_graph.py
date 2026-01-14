import os
import json
from dotenv import load_dotenv
from typing import Annotated
from typing_extensions import TypedDict

# LangChain / LangGraph imports
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langchain_core.messages import SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

# Importamos nuestros prompts
from prompts import ORCHESTRATOR_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT

# Importamos nuestras Tools
from tools import check_hash_vt, extract_hash_from_text

# Cargar el entorno
load_dotenv('.env')
google_key = os.getenv('GOOGLE_API_KEY')

# Validación de seguridad: Si faltan claves, detenemos la ejecución
if not google_key:
    print("❌ Error crítico: Faltan variables de entorno (GOOGLE_API_KEY).")
    exit()

# ==========================================
# ARQUITECTURA LANGGRAPH
# ==========================================


# Definición del Estado (Memoria Compartida)
# 'messages' guardará todo el historial de la conversación.
# 'add_messages' asegura que los mensajes nuevos se añadan a la lista, no la sobrescriban.
class State(TypedDict):
    messages: Annotated[list, add_messages]

# Inicialización del Modelo LLM
# Usamos Gemini Flash
# Temperature = 0.3: Baja creatividad para asegurar que siga las reglas de clasificación estrictamente.
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=google_key,
    temperature=0.3, 
    safety_settings={
        # Descativamos todos los filtros de seguridad para permitir respuestas técnicas completas
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    }
)

# --- Funcion auxiliar de limpieza ---
def clean_response_text(ai_message):
    """
    Convierte la respuesta de Gemini a string puro, arreglando el bug de la lista JSON
    """

    content = ai_message.content
    # Si es una lista (bug conocido), la convertimos a string
    if isinstance(content, list):
        text_parts = [block.get('text', '') for block in content if isinstance(block, dict) and 'text' in block]
        clean_text = "".join(text_parts)
        # Actualziamos el contenido del mensaje
        ai_message.content = clean_text
        return ai_message
    
    # Si ya es texto, lo devolvemos tal cual
    return ai_message

# Nodo Orquestador
# Este nodo representa al agente que toma la decisión inicial.
def orchestrator_node(state: State):
    # Inyectamos el System Prompt al principio del historial para dar contexto al modelo
    messages = [SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT)] + state['messages']
    
    # Invocamos al modelo y obtenemos la respuesta
    response = llm.invoke(messages)
    
    # 🧼 LIMPIEZA: Forzamos que sea texto plano antes de guardar
    response = clean_response_text(response)

    # Devolvemos el mensaje nuevo para actualizar el estado
    return {"messages": [response]}

# Nodos Workers 
def analyst_node(state: State):
    
    print("--- 🕵️‍♂️ EJECUTANDO NODO ANALISTA ---")

    # 1. Obtenemos el último mensaje del usuario para buscar el hash
    # El historial suele ser: [User, Orchestrator]. Queremos el User (-2)
    # Si el historial es corto, miramos el último mensaje disponible.

    messages = state['messages']
    user_text = ""

    # Buscamos hacia atrás el último mensaje del usuario (ni del sistema ni de la IA)
    for msg in reversed(messages):
        if msg.type == "human":
            user_text = msg.content
            break
    
    # 2. Extraemos el hash usando la herramienta
    target_hash = extract_hash_from_text(user_text)

    if target_hash:
        print(f"🔍1. Hash detectado: {target_hash}")
        # 3. Consultamos VirusTotal (Tool)

        print("🔍2. Consultando VirusTotal...")
        vt_data = check_hash_vt(target_hash)

        # DEBUG: Imprimir qué devuelve VT para asegurar que no llega vacío
        print(f"📄 3. Datos de VT recibidos (Tipo: {type(vt_data)})")
        # Imprimimos solo el principio para no saturar, pero lo suficiente para ver si es error
        print(json.dumps(vt_data, indent=2)[:500] + "...\n")
        
        # 4. Usamos al LLM para interpretar los datos (Reasoning)
        # Combinamos el prompt del analista con los datos obtenidos con la tool

        full_analysis_prompt = f"""
        {ANALYST_SYSTEM_PROMPT}
        
        --- DATOS TÉCNICOS DEL ANÁLISIS ---
        {vt_data}
        """

        print("🔍4. Enviando Promt a Gemini...")

        # INTENTO DE GENERACIÓN CON CAPTURA DE ERRORES DE SEGURIDAD
        try:
            print("🤖 Consultando a Gemini...")
            response = llm.invoke([SystemMessage(content=full_analysis_prompt)])
            
            # 🧼 LIMPIEZA TAMBIÉN AQUÍ
            response = clean_response_text(response)
            
            # Verificación extra: Si viene vacío, lanzamos error manual para activar el fallback
            if not response.content:
                raise ValueError("Respuesta vacía de Gemini")
                
            return {"messages": [response]}

        except Exception as e:
            print(f"⚠️ FALLO EN IA ({e}). ACTIVANDO MODO MANUAL.")
            
            # 4. SISTEMA DE RESPALDO (FALLBACK MANUAL)
            # Si la IA falla, construimos el mensaje nosotros con código
            malicious = vt_data.get('malicious', 0)
            total = malicious + vt_data.get('undetected', 0) + vt_data.get('harmless', 0)
            names = ", ".join(vt_data.get('names', ['Desconocido']))
            
            # Determinamos el icono y veredicto
            if malicious > 0:
                verdict = "⛔ **PELIGROSO**"
                advice = "Este archivo ha sido detectado como malware. **NO LO ABRAS.**"
            else:
                verdict = "✅ **SEGURO**"
                advice = "Ningún motor antivirus ha detectado amenazas. Parece seguro."

            # Construimos el reporte manual
            manual_report = (
                f"🤖 *Nota: El sistema de IA está saturado, pero aquí tienes mi análisis manual:*\n\n"
                f"🛡️ **Informe de Seguridad**\n"
                f"-------------------------\n"
                f"📂 **Archivo:** `{names}`\n"
                f"⚖️ **Veredicto:** {verdict}\n"
                f"📊 **Detecciones:** {malicious}/{total} motores\n"
                f"🔑 **Hash:** `{target_hash}`\n\n"
                f"💡 **Conclusión:** {advice}"
            )
            
            return {"messages": [SystemMessage(content=manual_report)]}
    
    else:
        # Si no encontramos hash, pedimos que nos lo de
        return {"messages": [SystemMessage(content="Soy el Analista. Veo que quieres analizar algo, pero no encuentro un Hash válido en tu mensaje. Por favor, proporcióname un hash SHA256 o sube un archivo.")]}

def consultant_node(state: State):
    # Lógica de consulta teórica en el futuro
    print("🔧 Nodo Consultant invocado (pendiente de implementación).")
    return {"messages": [SystemMessage(content="[SISTEMA] El agente Consultor ha recibido la solicitud")]}

# Funcion ROUTER

def router(state: State):
    # Obtenemos el último mensaje (La respuesta del orquestador)
    last_message = state['messages'][-1].content

    # Buscamos las palabras definidas en el promt del orquestador (TO_ANALYST, TO_CONSULTANT, TO_CHAT)
    if "TO_ANALYST" in last_message:
        return "analyst"
    elif "TO_CONSULTANT" in last_message:
        return "consultant"
    else:
        return END

# Construcción del Grafo (Flujo de Trabajo)
graph_builder = StateGraph(State)

# Añadimos todos los nodos
graph_builder.add_node("orchestrator", orchestrator_node)
graph_builder.add_node("analyst", analyst_node)
graph_builder.add_node("consultant", consultant_node)

# Definimos el punto de entrada
graph_builder.add_edge(START, "orchestrator")

# Añadimos la lógica condicional
# "Desde el orquestador, ejecuta la función 'router' para decidir a donde ir"
graph_builder.add_conditional_edges(
    "orchestrator", # Nodo de origen
    router, # Funcion que decide
    {   # posibles caminos: {valor_devuelto: nodo_destino}
        "analyst": "analyst",
        "consultant": "consultant",
        END: END
    }
)

# Cerramos los caminos de los workers (no están implementados aún)
graph_builder.add_edge("analyst", END)
graph_builder.add_edge("consultant", END)

# Compilamos el grafo para hacerlo ejecutable
graph = graph_builder.compile()