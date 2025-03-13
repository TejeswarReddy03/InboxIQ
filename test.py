from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_session import Session
import sqlite3
import requests
import os
import boto3
import json
import re
import base64
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.cloud import pubsub_v1

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE")
Session(app)

# Google OAuth2 settings
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")

# Google Cloud Pub/Sub settings
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT_ID")
TOPIC_NAME = os.getenv("PUBSUB_TOPIC_NAME")
SUBSCRIPTION_NAME = os.getenv("PUBSUB_SUBSCRIPTION_NAME")

# AWS Bedrock settings
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION_NAME = os.getenv("REGION_NAME")
MODEL_ID = os.getenv("MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")

# Initialize Bedrock client
bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name=REGION_NAME,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

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
                    encoded_data = part["body"]["data"].replace("-", "+").replace("_", "/")
                    decoded_data = base64.b64decode(encoded_data).decode("utf-8")
                    return decoded_data
        
        if "body" in payload and "data" in payload["body"]:
            encoded_data = payload["body"]["data"].replace("-", "+").replace("_", "/")
            decoded_data = base64.b64decode(encoded_data).decode("utf-8")
            return decoded_data
            
        if "snippet" in msg_data:
            return msg_data["snippet"]
            
        return ""
    except Exception as e:
        print(f"Error extracting email body: {str(e)}")
        return ""

def setup_gmail_watch(user_email, access_token):
    """
    Set up Gmail API watch for new emails using Google Cloud Pub/Sub
    """
    try:
        # Create credentials from access token
        credentials = Credentials(token=access_token)
        
        # Build the Gmail API service
        gmail_service = build('gmail', 'v1', credentials=credentials)
        
        # Set up watch on the user's inbox
        request = {
            'labelIds': ['INBOX'],
            'topicName': f'projects/{PROJECT_ID}/topics/{TOPIC_NAME}',
            'labelFilterAction': 'include'
        }
        
        response = gmail_service.users().watch(userId='me', body=request).execute()
        
        # Store history ID in Firebase
        user_ref = db.collection('users').document(user_email)
        user_ref.set({
            'gmail_history_id': response.get('historyId'),
            'gmail_expiration': response.get('expiration')
        }, merge=True)
        
        print(f"Successfully set up watch for {user_email}")
        return True
        
    except Exception as e:
        print(f"Error setting up Gmail watch: {str(e)}")
        return False

def process_history(user_email, access_token, history_id):
    """
    Process email history changes and update database
    """
    try:
        # Create credentials from access token
        credentials = Credentials(token=access_token)
        
        # Build the Gmail API service
        gmail_service = build('gmail', 'v1', credentials=credentials)
        
        # Get history changes
        response = gmail_service.users().history().list(
            userId='me', 
            startHistoryId=history_id,
            historyTypes='messageAdded'
        ).execute()
        
        # Process history changes
        histories = response.get('history', [])
        
        for history in histories:
            for message_added in history.get('messagesAdded', []):
                message = message_added.get('message', {})
                msg_id = message.get('id')
                
                if not msg_id:
                    continue
                    
                # Check if we've already processed this email
                email_ref = db.collection('emails').document(msg_id)
                if email_ref.get().exists:
                    continue
                
                # Get the message details
                msg_data = gmail_service.users().messages().get(userId='me', id=msg_id).execute()
                
                msg_headers = msg_data.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in msg_headers if h["name"].lower() == "subject"), "No Subject")
                sender = next((h["value"] for h in msg_headers if h["name"].lower() == "from"), "Unknown Sender")
                body = get_email_body(msg_data)
                
                # Process with Claude
                has_apps, detected_apps = detect_third_party_apps(body)
                
                # Store in Firestore
                email_ref.set({
                    'email_id': msg_id,
                    'user_email': user_email,
                    'subject': subject,
                    'sender': sender,
                    'body': body,
                    'has_third_party_apps': has_apps,
                    'detected_apps': detected_apps,
                    'created_at': firestore.SERVER_TIMESTAMP
                })
                
                print(f"Processed new email: {subject}")
        
        # Update the history ID
        if 'historyId' in response:
            user_ref = db.collection('users').document(user_email)
            user_ref.set({
                'gmail_history_id': response['historyId']
            }, merge=True)
            
        return True
        
    except Exception as e:
        print(f"Error processing history: {str(e)}")
        return False

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
        "&scope=openid%20email%20profile%20https://www.googleapis.com/auth/gmail.readonly"
        "&access_type=offline"  # This requests a refresh token
        "&prompt=consent"  # Force getting a new refresh token
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
    refresh_token = token_json.get("refresh_token")

    if not access_token:
        return "Authentication failed. Please try again."

    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    user_info_response = requests.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
    user_info = user_info_response.json()
    email = user_info.get("email")

    if not email:
        return "Failed to retrieve user email."

    # Store in Firestore
    user_ref = db.collection('users').document(email)
    user_ref.set({
        'email': email,
        'refresh_token': refresh_token,  # Store refresh token for later use
        'last_login': firestore.SERVER_TIMESTAMP,
        'active': True
    }, merge=True)

    # Store token in session
    session["email"] = email
    session["access_token"] = access_token

    # Set up Gmail API watch for this user
    setup_gmail_watch(email, access_token)
    
    # Initial fetch of messages
    fetch_initial_messages(email, access_token)

    return redirect(url_for("dashboard"))