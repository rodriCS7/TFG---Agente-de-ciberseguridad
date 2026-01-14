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

# Cargamos las claves desde el archivo .env para no exponerlas en el código
load_dotenv('.env') 

telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')

# Validación de seguridad: Si faltan claves, detenemos la ejecución
if not telegram_token:
    print("❌ Error crítico: Faltan variables de entorno (TELEGRAM_BOT_TOKEN).")
    exit()

# ==========================================
# INTERFAZ DE TELEGRAM (LA CAPA DE VISTA)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Responde al comando /start iniciando la interacción."""
    await update.message.reply_text('¡Hola! Soy SecMate 1.0. ¿En qué puedo ayudarte hoy?')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Maneja cualquier mensaje de texto entrante.
    Actúa como puente entre Telegram y LangGraph.
    """
    user_text = update.message.text
    print(f"📩 Usuario dice: {user_text}")

    # Convertimos el texto de Telegram a un formato que entienda LangChain
    input_message = HumanMessage(content=user_text)

    try:
        # Ejecutamos el grafo con el mensaje del usuario
        final_state = graph.invoke({'messages': [input_message]})
        
        # Extraemos la última respuesta generada por la IA
        bot_response = final_state['messages'][-1].content

        # --- GESTIÓN DE LÍMITES DE TELEGRAM ---
        # Telegram tiene un límite de 4096 caracteres.
        # Cortamos en 4000 para dejar margen a negritas y formato Markdown.
        max_length = 4000 

        if len(bot_response) > max_length:
            # Algoritmo de segmentación: Divide el mensaje en trozos de 4000 caracteres
            for i in range(0, len(bot_response), max_length):
                await update.message.reply_text(bot_response[i:i+max_length])
        else:
            # Envío normal
            await update.message.reply_text(bot_response)

    except Exception as e:
        print(f"❌ Error en el sistema: {e}")
        await update.message.reply_text("Lo siento, ha ocurrido un error interno al procesar tu solicitud.")

# ==========================================
# 5. PUNTO DE ENTRADA (MAIN)
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