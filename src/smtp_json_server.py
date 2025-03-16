import asyncio
import base64
import email
import json
import logging
import os
import smtpd
import asyncore
import threading
import time
from email.policy import default
from http.client import HTTPConnection, HTTPSConnection
from typing import Dict, Any
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-webhook')

class WebhookSMTPServer(smtpd.SMTPServer):
    """
    SMTP Server that forwards emails to a webhook
    """
    def __init__(self, host, port, webhook_url):
        super().__init__((host, port), None)
        self.webhook_url = webhook_url
        logger.info(f"Webhook URL configured: {webhook_url}")
        
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        """Process incoming message and forward to webhook"""
        try:
            # Parse the email message
            message = email.message_from_bytes(data, policy=default)
            
            # Extract email data
            email_data = self._extract_email_data(message, mailfrom, rcpttos)
            
            # Send to webhook
            self._send_webhook(email_data)
            
            logger.info(f"Processed message from {mailfrom} to {rcpttos}")
            return None  # Indicate successful processing
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}", exc_info=True)
            return f"500 Error processing message: {str(e)}"

    def _extract_email_data(self, message, mailfrom, rcpttos) -> Dict[str, Any]:
        """Extract all relevant data from the email message"""
        # Get basic headers
        email_data = {
            "from": mailfrom,
            "to": rcpttos,
            "subject": message.get("Subject", ""),
            "date": message.get("Date", ""),
            "message_id": message.get("Message-ID", ""),
            "headers": {k: v for k, v in message.items()},
            "body": {
                "plain": "",
                "html": ""
            },
            "attachments": []
        }

        # Process each part of the email
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            
            # Extract body parts
            if content_disposition is None:
                if content_type == "text/plain":
                    try:
                        email_data["body"]["plain"] = part.get_content()
                    except:
                        # Fallback for older email formats
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_data["body"]["plain"] = payload.decode('utf-8', errors='replace')
                elif content_type == "text/html":
                    try:
                        email_data["body"]["html"] = part.get_content()
                    except:
                        # Fallback for older email formats
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_data["body"]["html"] = payload.decode('utf-8', errors='replace')
            
            # Extract attachments
            elif content_disposition == "attachment":
                filename = part.get_filename()
                if filename:
                    # Get payload and encode to base64
                    payload = part.get_payload(decode=True)
                    if payload:
                        encoded_payload = base64.b64encode(payload).decode('utf-8')
                        
                        email_data["attachments"].append({
                            "filename": filename,
                            "content_type": content_type,
                            "content": encoded_payload
                        })
        
        return email_data

    def _send_webhook(self, email_data: Dict[str, Any]) -> None:
        """Send the email data to the webhook URL"""
        try:
            # Parse the webhook URL
            url = urlparse(self.webhook_url)
            is_https = url.scheme == 'https'
            
            # Prepare the connection
            if is_https:
                conn = HTTPSConnection(url.netloc)
            else:
                conn = HTTPConnection(url.netloc)
            
            # Prepare the request body
            body = json.dumps(email_data)
            
            # Send the request
            path = url.path
            if url.query:
                path += '?' + url.query
            
            conn.request(
                "POST", 
                path, 
                body=body, 
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body))
                }
            )
            
            # Get the response
            response = conn.getresponse()
            status = response.status
            
            if status < 200 or status >= 300:
                response_text = response.read().decode('utf-8')
                logger.error(f"Webhook responded with status {status}: {response_text}")
            else:
                logger.info(f"Webhook delivery successful: {status}")
            
            conn.close()
        except Exception as e:
            logger.error(f"Failed to send webhook: {str(e)}", exc_info=True)

def run_smtp_server():
    """Run the SMTP server"""
    # Get configuration from environment variables
    smtp_host = os.environ.get('SMTP_HOST', '0.0.0.0')
    smtp_port = int(os.environ.get('SMTP_PORT', 25))
    webhook_url = os.environ.get('WEBHOOK_URL')
    
    if not webhook_url:
        logger.error("WEBHOOK_URL environment variable is required")
        return
    
    try:
        logger.info(f"Starting SMTP webhook forwarder on {smtp_host}:{smtp_port}")
        server = WebhookSMTPServer(smtp_host, smtp_port, webhook_url)
        
        # Run asyncore loop in the main thread
        asyncore.loop()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # Run the server
    run_smtp_server()