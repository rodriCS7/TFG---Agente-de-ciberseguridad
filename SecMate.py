import os
from dotenv import load_dotenv
# Telegram: Librerías para interactuar con la API del bot
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from langchain_core.messages import HumanMessage

# ==========================================
# CONFIGURACIÓN DEL ENTORNO
# ==========================================

# Importamos el grafo
from agent_graph import graph

# Importamos las funciones / Tools necesarias
from tools import get_file_hash

# Cargamos las claves desde el archivo .env para no exponerlas en el código
load_dotenv('.env') 

telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')

# Validación de seguridad: Si faltan claves, detenemos la ejecución
if not telegram_token:
    print("❌ Error crítico: Faltan variables de entorno (TELEGRAM_BOT_TOKEN).")
    exit()

# ==========================================
# FUNCIONES AUXILIARES
# ==========================================

async def process_with_graph(update: Update, text_input: str):
    """
    Función auxiliar que envía cualquier texto al Grafo y gestiona la respuesta.
    Se usa tanto para mensajes de texto normales como para archivos (tras calcular su hash).
    """
    try:
        # Convertimos a formato LangChain
        input_message = HumanMessage(content=text_input)
        
        # Ejecutamos el grafo
        final_state = graph.invoke({'messages': [input_message]})
        bot_response = final_state['messages'][-1].content
        
        # Gestión de límites de Telegram (4096 caracteres)
        max_length = 4000
        if len(bot_response) > max_length:
            for i in range(0, len(bot_response), max_length):
                await update.message.reply_text(bot_response[i:i+max_length])
        else:
            await update.message.reply_text(bot_response)
            
    except Exception as e:
        print(f"❌ Error en el grafo: {e}")
        await update.message.reply_text("Lo siento, ha ocurrido un error interno al procesar tu solicitud.")

# ==========================================
# HANDLERS DE TELEGRAM
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Responde al comando /start iniciando la interacción."""
    await update.message.reply_text('¡Hola! Soy SecMate 1.0. ¿En qué puedo ayudarte hoy?')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """ Maneja texto normal enviado por el usuario. """

    user_text = update.message.text
    print(f"📩 Usuario dice: {user_text}")

    await process_with_graph(update, user_text)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """"
    Maneja la subida de archivos.
    1. Descarga -> 2. Calcula el Hash -> 3. Borra el archivo -> 4. Envía el hash al grafo.
    """

    # Aviso inicial
    status_message = await update.message.reply_text("📥 Archivo recibido. Procesando...")

    download_path = None # Variable para guardar la ruta

    try:
        # 1. Obtener info del archivo
        file = await update.message.document.get_file()
        file_name = update.message.document.file_name

        # 2. Descargar el archivo a una ruta temporal
        download_path = f"temp_{file_name}"
        await file.download_to_drive(download_path)

        # 3. Calcular el Hash (Usando la funcion de tools.py)
        file_hash = get_file_hash(download_path)

        # 4. Limpieza: Borrar el archivo temporal
        if os.path.exists(download_path):
            os.remove(download_path)
        
        if file_hash:
            await status_message.edit_text(f"✅ Hash calculado: `{file_hash}`\n🕵️‍♂️ Consultando al Analista...")

            # 5. Creamos un prompt simulando que el usuario envía el hash
            simulated_user_input = f"Analiza el hash: {file_hash} del archivo llamado {file_name}"

            # Enviamos este texto al Grafo
            await process_with_graph(update, simulated_user_input)
        else:
            await status_message.edit_text("❌ No se pudo calcular el hash del archivo.")
    
    except Exception as e:
        print(f"❌ Error al procesar el archivo: {e}")
        # Limpiamos en caso de error
        if download_path and os.path.exists(download_path):
            os.remove(download_path)
        await status_message.edit_text("❌ Ha ocurrido un error al procesar el archivo.")
        
        
# ==========================================
# PUNTO DE ENTRADA (MAIN)
# ==========================================
if __name__ == "__main__":
    # Construimos la aplicación de Telegram
    app = ApplicationBuilder().token(telegram_token).build()

    # Registramos los manejadores (Handlers)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 SecMate está escuchando...")
    # Iniciamos el bucle de escucha (Polling)
    app.run_polling()