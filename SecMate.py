import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Importamos las librerias de Google

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing import Annotated
from typing_extensions import TypedDict

# 1. Cargar el entorno
load_dotenv('.env')
telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
google_key = os.getenv('GOOGLE_API_KEY')

# Verificar que las variables de entorno se han cargado correctamente
if not telegram_token or not google_key:
    print("Error: Missing TELEGRAM_BOT_TOKEN or GOOGLE_API_KEY in environment variables.")
    exit()

# ----- CONFIGURACIÓN DE LANGGRAPH -----

# A. Estado
class State(TypedDict):
    messages: Annotated[list, add_messages]

# B. Inicializamos el modelo (Gemini PRO)
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=google_key,
    temperature=0.7,
)

# C. Nodo Chatbot
def chatbot_node(state: State):
    return {"messages": [llm.invoke(state['messages'])]}

# D. Construimos el grafo
graph_builder = StateGraph(State)
graph_builder.add_node("chatbot", chatbot_node)
graph_builder.add_edge(START, "chatbot")
graph_builder.add_edge("chatbot", END)
graph = graph_builder.compile()


# ----- CONFIGURACIÓN DE TELEGRAM -----

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text('¡Hola! Soy SecMate (vía Google Gemini). ¿En qué puedo ayudarte hoy?')

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_text = update.message.text
    print(f"Usuario: {user_text}")

    # Invocamos al grafo
    input_message = ("user", user_text)
    try:
        final_state = graph.invoke({ 'messages': [input_message]})
        bot_response = final_state['messages'][-1].content

        # Telegram tiene un límite de 4096 caracteres por mensaje
        # Usamos 4000 para el formato markdown en el futuro
        max_lenght = 4000

        if len(bot_response) > max_lenght:
            # Dividimos la respuesta en partes
            for i in range(0, len(bot_response), max_lenght):
                await update.message.reply_text(bot_response[i:i+max_lenght])
        else:
            # Si es corto, enviamos todo de una vez
            await update.message.reply_text(bot_response)

    except Exception as e:
        print(f"❌ Error en Gemini: {e}")
        await update.message.reply_text("Lo siento, ha ocurrido un error al procesar tu solicitud.")

# ----- EJECUCIÓN DEL BOT -----
if __name__ == "__main__":
    app = ApplicationBuilder().token(telegram_token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 SecMate está escuchando...")
    app.run_polling()
