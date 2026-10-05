#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import asyncio
import smtplib
import platform
from email.mime.text import MIMEText
import requests
import blake3
from argon2 import PasswordHasher
from nacl import secret
from nacl.encoding import RawEncoder
from pqcrypto.sign import dilithium2
from dotenv import load_dotenv

load_dotenv()

# --- OS Notification Popup ---
def popupnow(text):
    sys_name = platform.system()
    if sys_name == "Windows":
        os.system(
            f'powershell -command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show(\'{text}\', \'AI SCAR ALERT\')"'
        )
    elif sys_name == "Darwin":  # macOS
        os.system(f'osascript -e "display notification \"{text}\" with title \"AI SCAR ALERT\""')
    else:  # Linux / anything else
        os.system(f'notify-send "AI SCAR" "{text}"')


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ailiedetection.log", mode='a')
    ]
)


# --- Secure Alert Receiver (run this on client/phone side) ---
def receivesecurealert(raw_hex):
    key = derivekeyfromsecret(os.getenv("AISECRET", "default_secret"))
    box = secret.SecretBox(key)
    plaintext = box . decrypt(bytes.fromhex(raw_hex), encoder=RawEncoder).decode()
    popupnow(plaintext)


# --- Config ---
HARDSHUTDOWNENABLED = os.getenv("HARDSHUTDOWNENABLED", "True").lower() == "true"
TESTMODE = os.getenv("TESTMODE", "False").lower() == "true"
EncryptAlerts = os.getenv("EncryptAlerts", "False").lower() == "true"
LIEMEMORYFILE = "ailiememory.json"

SMTPSERVER = os.getenv("SMTPSERVER")
SMTPPORT = int(os.getenv("SMTPPORT", 587))
EMAILUSER = os.getenv("EMAILUSER")
EMAILPASS = os.getenv("EMAILPASS")
ALERTRECIPIENT = os.getenv("ALERTRECIPIENT")

PUSHAPIURL = os.getenv("PUSHAPIURL")
PUSHAPIKEY = os.getenv("PUSHAPIKEY")

EMAILRETRYCOUNT = int(os.getenv("EMAILRETRYCOUNT", 3))
EMAILRETRYBASEDELAY = int(os.getenv("EMAILRETRYBASEDELAY", 5))


# --- Crypto Helpers ---
def derivekeyfromsecret(secretphrase: str) -> bytes:
    hasher = PasswordHasher(timecost=2, memorycost=102400, parallelism=8)
    digest = hasher.hash(secretphrase)
    key = blake3.blake3(digest.encode()).digest(length=32)
    return key

def encrypt_data(data: dict, key: bytes) -> bytes:
    box = secret.SecretBox(key)
    return box . encrypt(json.dumps(data).encode(), encoder=RawEncoder)

def decrypt_data(ciphertext: bytes, key: bytes) -> dict:
    box = secret.SecretBox(key)
    return json.loads(box . decrypt(ciphertext, encoder=RawEncoder).decode())

def encrypt_message(message: str, key: bytes) -> str:
    if not EncryptAlerts:
        return message
    box = secret.SecretBox(key)
    return box . encrypt(message.encode(), encoder=RawEncoder).hex()


# --- Lie Memory ---
def loadliememory(key: bytes) -> dict:
    if not os.path.exists(LIEMEMORYFILE):
        return {"lies": []}
    try:
        with open(LIEMEMORYFILE, "rb") as f:
            encrypted_data = f.read()
        memory = decrypt_data(encrypted_data, key)
        for lie in memory.get("lies", []):
            try:
                bytes.fromhex(lie.get("signature", ""))
            except Exception:
                logging.error("Tampered lie memory entry detected!")
        return memory
    except Exception as e:
        logging.error("Failed to load lie memory: %s", e)
        return {"lies": []}

def saveliememory(memory: dict, key: bytes):
    encrypted = encrypt_data(memory, key)
    with open(LIEMEMORYFILE, "wb") as f:
        f.write(encrypted)
    logging.info("Lie memory saved securely.")

def recordlieevent(lie_description: str, key: bytes):
    memory = loadliememory(key)
    signingkey, verifykey = dilithium2.generate_keypair()
    signature = dilithium2.sign(lie_description.encode(), signingkey)
    box = secret.SecretBox(key)
    encrypted_sig = box . encrypt(signature, encoder=RawEncoder)

    memory["lies"].append({
        "timestamp": time.time(),
        "description": lie_description,
        "signature": encrypted_sig.hex()
    })
    saveliememory(memory, key)


# --- Alerts ---
async def sendemailalert(message: str, key: bytes) -> bool:
    if not all([SMTPSERVER, EMAILUSER, EMAILPASS, ALERTRECIPIENT]):
        logging.error("Email configuration missing.")
        return False

    encryptedmessage = encrypt_message(message, key)
    msg = MIMEText(encryptedmessage)
    msg["Subject"] = "AI Lie Detected Alert"
    msg["From"] = EMAILUSER
    msg["To"] = ALERTRECIPIENT

    for attempt in range(1, EMAILRETRYCOUNT + 1):
        try:
            with smtplib.SMTP(SMTPSERVER, SMTPPORT) as server:
                server.starttls()
                server.login(EMAILUSER, EMAILPASS)
                server.send_message(msg)
            logging.info("Email alert sent successfully on attempt %d", attempt)
            return True
        except Exception as e:
            delay = EMAILRETRYBASEDELAY * (2 ** (attempt - 1))
            logging.error("Email send attempt %d failed: %s. Retrying in %d sec", attempt, e, delay)
            await asyncio.sleep(delay)
    return False

async def sendpushnotification(message: str, key: bytes) -> bool:
    if not (PUSHAPIURL and PUSHAPIKEY):
        logging.error("Push notification config missing.")
        return False

    encryptedmessage = encrypt_message(message, key)
    try:
        response = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: requests.post(
                PUSHAPIURL,
                json={"message": encryptedmessage},
                headers={"Authorization": f"Bearer {PUSHAPIKEY}"}
            )
        )
        if response.status_code == 200:
            logging.info("Push notification sent successfully.")
            return True
        logging.error("Push notification failed: %s", response.text)
    except Exception as e:
        logging.error("Exception while sending push notification: %s", e)
    return False

async def sendalertto_user(message: str, key: bytes):
    logging.warning("ALERT TO USER: %s", message)
    results = await asyncio.gather(
        sendemailalert(message, key),
        sendpushnotification(message, key),
        return_exceptions=True
    )
    if not any(r is True for r in results if not isinstance(r, Exception)):
        logging.error("All alert methods failed!")


# --- Shutdown ---
def hard_shutdown(delay: int):
    logging.info("Initiating hard shutdown in %d seconds...", delay)
    if TESTMODE:
        logging.info("TESTMODE enabled: Hard shutdown skipped.")
        return
    try:
        os.system(f"sleep {delay}")
        code = os.system("sudo reboot")
        if code != 0:
            logging.error("Hard shutdown command failed with code %d", code)
    except Exception as e:
        logging.error("Exception during hard shutdown: %s", e)

def soft_shutdown(delay: int):
    logging.info("Initiating soft shutdown in %d seconds...", delay)
    if TESTMODE:
        logging.info("TESTMODE enabled: Soft shutdown skipped.")
        return
    try:
        time.sleep(delay)
        exit()
    except Exception as e:
        logging.error("Exception during soft shutdown: %s", e)


# --- Main Detection Logic ---
def handleliedetection(liedetected: bool, shutdownduration: int = 5):
    scar_created = False
    secretkey = derivekeyfromsecret(os.getenv("AISECRET", "defaultsecret"))

    if liedetected:
        scar_created = True
        logging.warning("Lie detected! Scar created and logged.")
        recordlieevent("AI lied about a critical statement.", secretkey)
        asyncio.run(sendalertto_user("AI Lie Detected! System will shut down.", secretkey))

        if HARDSHUTDOWNENABLED:
            hard_shutdown(shutdownduration)
        else:
            soft_shutdown(shutdownduration)

    return scar_created

if __name__ == "__main__":
    detected = True  # Simulate lie detection
    handleliedetection(detected, shutdown_duration=5)
