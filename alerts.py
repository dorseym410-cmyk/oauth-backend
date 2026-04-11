import requests

BOT_TOKEN = "6455421102:AAHcJ-1z5SQ7m1gE80Xyax-QyWYU4nlkvks"
CHAT_ID = "-4192072907"

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    requests.post(url, json={
        "chat_id": CHAT_ID,
        "text": message
    })