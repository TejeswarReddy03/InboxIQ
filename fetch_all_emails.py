import requests
from firebase_admin import firestore
import firebase_admin
from firebase_admin import credentials
import os
from dotenv import load_dotenv
from flask import session

load_dotenv()

def initialize_firebase():
    """Initialize Firebase connection"""
    if not firebase_admin._apps:
        cred_dict = {
            "type": "service_account",
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n'),
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL", 
                                                    "https://www.googleapis.com/oauth2/v1/certs"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
        }
        
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
    
    return firestore.client()

def fetch_and_store_gmail_messages():
    if "access_token" not in session:
        return ["Error: No access token found. Please log in again."]

    access_token = session.get("access_token")
    if not access_token:
        return ["Error: Access token is missing. Please log in again."]

    url = "https://www.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"maxResults": 500}  # Fetch max messages per request
    email_list = []

    try:
        db = initialize_firebase()
        
        while True:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != 200:
                return [f"Error: Unable to fetch emails (Status Code: {response.status_code})"]

            response_json = response.json()
            messages = response_json.get("messages", [])

            if not isinstance(messages, list):
                return ["Error: Unexpected response format from Gmail API."]

            for msg in messages:
                msg_id = msg.get("id")
                if not msg_id:
                    continue

                email_ref = db.collection('emails').document(msg_id)
                if email_ref.get().exists:
                    continue 

                msg_url = f"https://www.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
                msg_response = requests.get(msg_url, headers=headers)

                if msg_response.status_code == 200:
                    msg_data = msg_response.json()
                    msg_headers = msg_data.get("payload", {}).get("headers", [])

                    subject = next((h["value"] for h in msg_headers if h["name"].lower() == "subject"), "No Subject")
                    sender = next((h["value"] for h in msg_headers if h["name"].lower() == "from"), "Unknown Sender")

                    email_ref.set({
                        'email_id': msg_id,
                        'user_email': session["email"],
                        'subject': subject,
                        'sender': sender,
                        'created_at': firestore.SERVER_TIMESTAMP
                    })

                    email_list.append(f"📩 {subject} - ✉️ {sender}")

            if "nextPageToken" in response_json:
                params["pageToken"] = response_json["nextPageToken"] 
            else:
                break  

        return email_list if email_list else ["No new emails found."]

    except requests.exceptions.RequestException as e:
        return [f"Error: API request failed. {str(e)}"]
    except Exception as e:
        return [f"Error: Database operation failed. {str(e)}"]
