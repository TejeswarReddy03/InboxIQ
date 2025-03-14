from flask import Flask, redirect, url_for, session, request, render_template
from flask_session import Session
import sqlite3
import requests
import os
import boto3
import json
import re
import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE")
Session(app)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION_NAME = os.getenv("REGION_NAME")

MODEL_ID = os.getenv("MODEL_ID")

bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name=REGION_NAME,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"

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

db = initialize_firebase()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        "?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        "&redirect_uri=http://127.0.0.1:5000/auth/callback"
        "&scope=openid%20email%20profile%20https://mail.google.com/"
        "&access_type=offline"
        "&prompt=consent"
    )
    return redirect(google_auth_url)

@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")

    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": "http://127.0.0.1:5000/auth/callback",
        "grant_type": "authorization_code",
    }
    token_response = requests.post(token_url, data=token_data)
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")  # Also capture the refresh token if available
    token_expiry = token_json.get("expires_in")  # Get token expiration time
    
    print(access_token)

    if not access_token:
        return "Authentication failed. Please try again."

    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    user_info_response = requests.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
    user_info = user_info_response.json()
    email = user_info.get("email")

    if not email:
        return "Failed to retrieve user email."
    
    current_time = datetime.datetime.now()
    expiry_time = None
    
    if token_expiry:
        expiry_time = current_time + datetime.timedelta(seconds=int(token_expiry))

    user_ref = db.collection('users').document(email)
    user_data = {
        'email': email,
        'access_token': access_token,
        'token_updated_at': firestore.SERVER_TIMESTAMP,
    }
    
    if refresh_token:
        user_data['refresh_token'] = refresh_token
    
    if expiry_time:
        user_data['token_expires_at'] = expiry_time
    
    user_ref.set(user_data, merge=True)

    session["email"] = email
    session["access_token"] = access_token

    return redirect(url_for("dashboard"))

def get_user_access_token(email):
    """
    Retrieve the access token for a user from Firestore.
    If token is expired, try to refresh it.
    
    Args:
        email (str): User's email address
        
    Returns:
        str: Valid access token or None if not available
    """
    try:
        user_ref = db.collection('users').document(email)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return None
            
        user_data = user_doc.to_dict()
        access_token = user_data.get('access_token')
        
        # Check if token is expired
        current_time = datetime.datetime.now()
        expires_at = user_data.get('token_expires_at')
        
        if expires_at and current_time >= expires_at.replace(tzinfo=None):
            refresh_token = user_data.get('refresh_token')
            if refresh_token:
                new_token = refresh_access_token(refresh_token, email)
                if new_token:
                    return new_token
                    
            return None
            
        return access_token
    
    except Exception as e:
        print(f"Error retrieving user token: {str(e)}")
        return None

def refresh_access_token(refresh_token, email):
    """
    Refresh an expired access token using the refresh token.
    
    Args:
        refresh_token (str): The refresh token
        email (str): User's email to update in Firestore
        
    Returns:
        str: New access token or None if refresh failed
    """
    try:
        token_url = "https://oauth2.googleapis.com/token"
        refresh_data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        token_response = requests.post(token_url, data=refresh_data)
        
        if token_response.status_code != 200:
            print(f"Failed to refresh token: {token_response.text}")
            return None
            
        token_json = token_response.json()
        new_access_token = token_json.get("access_token")
        token_expiry = token_json.get("expires_in")
        
        if new_access_token and email:
            current_time = datetime.datetime.now()
            expiry_time = None
            
            if token_expiry:
                expiry_time = current_time + datetime.timedelta(seconds=int(token_expiry))
                
            user_ref = db.collection('users').document(email)
            user_data = {
                'access_token': new_access_token,
                'token_updated_at': firestore.SERVER_TIMESTAMP,
            }
            
            if expiry_time:
                user_data['token_expires_at'] = expiry_time
                
            user_ref.set(user_data, merge=True)
        
        return new_access_token
        
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return None

def detect_third_party_apps(email_content):
    """
    Use Claude to detect third-party apps mentioned in the email content.
    
    Returns:
        tuple: (has_apps, detected_apps_list)
    """
    try:
        if len(email_content) < 50:
            return False, []
            
        user_prompt = f"Analyze this email and extract all third-party applications, services, and platforms mentioned. Only return names of services and platforms, not common email elements. Return the result as a JSON array with just the names. If no apps are mentioned, return an empty array. Here's the email:\n\n{email_content}"
        
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 300,
            "messages": [
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        }
        
        response = bedrock.invoke_model(
            body=json.dumps(payload),
            modelId=MODEL_ID,
            accept="application/json",
            contentType="application/json"
        )
        
        response_body = json.loads(response["body"].read())
        response_content = response_body["content"][0]["text"]
        
        match = re.search(r'\[.*?\]', response_content, re.DOTALL)
        if match:
            try:
                apps_list = json.loads(match.group(0))
                
                apps_list = [app for app in apps_list if app and app.strip() and len(app) > 1]
                return bool(apps_list), apps_list
            except json.JSONDecodeError:
                apps_list = re.findall(r'"([^"]+)"', match.group(0))
                apps_list = [app for app in apps_list if app and app.strip() and len(app) > 1]
                return bool(apps_list), apps_list
        else:
            lines = response_content.split('\n')
            potential_apps = []
            for line in lines:
                if ':' in line:  
                    potential_app = line.split(':', 1)[1].strip()
                    if potential_app and len(potential_app) > 1:
                        potential_apps.append(potential_app)
                elif '-' in line:  
                    potential_app = line.split('-', 1)[1].strip()
                    if potential_app and len(potential_app) > 1:
                        potential_apps.append(potential_app)
            
            return bool(potential_apps), potential_apps
            
    except Exception as e:
        print(f"Error in third-party app detection: {str(e)}")
        return False, []

def get_email_body(msg_data):
    """Extract email body from Gmail API response."""
    try:
        payload = msg_data.get("payload", {})
        
        if "parts" in payload:
            for part in payload["parts"]:
                mime_type = part.get("mimeType", "")
                if mime_type == "text/plain" and "body" in part and "data" in part["body"]:
                    import base64
                    
                    encoded_data = part["body"]["data"].replace("-", "+").replace("_", "/")
                    decoded_data = base64.b64decode(encoded_data).decode("utf-8")
                    return decoded_data
        
        if "body" in payload and "data" in payload["body"]:
            import base64
            encoded_data = payload["body"]["data"].replace("-", "+").replace("_", "/")
            decoded_data = base64.b64decode(encoded_data).decode("utf-8")
            return decoded_data
            
        if "snippet" in msg_data:
            return msg_data["snippet"]
            
        return ""
    except Exception as e:
        print(f"Error extracting email body: {str(e)}")
        return ""

def fetch_and_store_gmail_messages():
    """Fetch and store emails from Gmail to Firestore"""
    if "email" not in session:
        return []

    email = session.get("email")
    
    # Try to get token from session first
    access_token = session.get("access_token")
    
    # If token not in session, get from database
    if not access_token:
        access_token = get_user_access_token(email)
        if access_token:
            # Update session with the token from database
            session["access_token"] = access_token
    
    if not access_token:
        return []

    url = "https://www.googleapis.com/gmail/v1/users/me/messages?maxResults=10"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            # Handle token expiration error (status 401)
            if response.status_code == 401:
                # Try to refresh token
                user_ref = db.collection('users').document(email)
                user_doc = user_ref.get()
                
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    refresh_token = user_data.get('refresh_token')
                    
                    if refresh_token:
                        new_access_token = refresh_access_token(refresh_token, email)
                        if new_access_token:
                            # Update session
                            session["access_token"] = new_access_token
                            
                            # Try request again with new token
                            headers = {"Authorization": f"Bearer {new_access_token}"}
                            response = requests.get(url, headers=headers)
                            
                            if response.status_code != 200:
                                return []
                        else:
                            return []
                    else:
                        return []
                else:
                    return []
            else:
                return []

        response_json = response.json()
        messages = response_json.get("messages", [])

        processed_emails = []
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
                body = get_email_body(msg_data)
                
                has_apps, detected_apps = detect_third_party_apps(body)
                
                email_ref.set({
                    'email_id': msg_id,
                    'user_email': session["email"],
                    'subject': subject,
                    'sender': sender,
                    'body': body,
                    'has_third_party_apps': has_apps,
                    'detected_apps': detected_apps,
                    'created_at': firestore.SERVER_TIMESTAMP
                })
                
                if has_apps:
                    processed_emails.append({
                        "subject": subject,
                        "sender": sender,
                        "apps": detected_apps
                    })

        return processed_emails
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return []

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("home"))

    fetch_and_store_gmail_messages()
    
    try:
        emails_ref = db.collection('emails')
        query = emails_ref.where('user_email', '==', session["email"]).where('has_third_party_apps', '==', True)
        docs = query.stream()
        
        app_emails = []
        for doc in docs:
            data = doc.to_dict()
            app_emails.append({
                'subject': data.get('subject', 'No Subject'),
                'sender': data.get('sender', 'Unknown Sender'),
                'apps': data.get('detected_apps', [])
            })
    except Exception as e:
        print(f"Firestore error: {str(e)}")
        app_emails = []
    
    return render_template("index2.html", email=session["email"], app_emails=app_emails)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)