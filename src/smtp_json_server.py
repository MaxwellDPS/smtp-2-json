import asyncio
import base64
import email
import json
import logging
import os
from email.policy import default
from typing import Dict, List, Any, Optional

import aiohttp
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smtp-webhook')

class WebhookHandler(AsyncMessage):
    """
    SMTP Handler that forwards messages as JSON to a webhook URL
    """
    def __init__(self, webhook_url: str):
        super().__init__()
        self.webhook_url = webhook_url
        logger.info(f"Webhook URL configured: {webhook_url}")

    async def handle_message(self, message):
        """Process the email message and forward it to the webhook"""
        try:
            # Parse the email message if it's bytes
            if isinstance(message, bytes):
                message = email.message_from_bytes(message, policy=default)
            
            # Extract email data
            email_data = await self._extract_email_data(message)
            
            # Send to webhook
            await self._send_webhook(email_data)
            
            return '250 Message accepted for delivery'
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}", exc_info=True)
            return '500 Error processing message'

    async def _extract_email_data(self, message) -> Dict[str, Any]:
        """Extract all relevant data from the email message"""
        # Get basic headers
        email_data = {
            "from": message.get("From", ""),
            "to": message.get("To", ""),
            "cc": message.get("Cc", ""),
            "bcc": message.get("Bcc", ""),
            "subject": message.get("Subject", ""),
            "date": message.get("Date", ""),
            "message_id": message.get("Message-ID", ""),
            "headers": dict(message.items()),
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
                    email_data["body"]["plain"] = part.get_content()
                elif content_type == "text/html":
                    email_data["body"]["html"] = part.get_content()
            
            # Extract attachments
            elif content_disposition == "attachment":
                filename = part.get_filename()
                if filename:
                    # Get payload and encode to base64
                    payload = part.get_payload(decode=True)
                    encoded_payload = base64.b64encode(payload).decode('utf-8')
                    
                    email_data["attachments"].append({
                        "filename": filename,
                        "content_type": content_type,
                        "content": encoded_payload
                    })
        
        return email_data

    async def _send_webhook(self, email_data: Dict[str, Any]) -> None:
        """Send the email data to the webhook URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=email_data,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status < 200 or response.status >= 300:
                        response_text = await response.text()
                        logger.error(f"Webhook responded with status {response.status}: {response_text}")
                    else:
                        logger.info(f"Webhook delivery successful: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send webhook: {str(e)}", exc_info=True)
            raise

class SMTPWebhookServer:
    """
    SMTP server that forwards emails to a webhook
    """
    def __init__(
        self, 
        host: str, 
        port: int, 
        webhook_url: str
    ):
        self.host = host
        self.port = port
        self.webhook_url = webhook_url
        self.handler = WebhookHandler(webhook_url)
        self.controller = None

    async def start(self) -> None:
        """Start the SMTP server"""
        self.controller = Controller(
            self.handler,
            hostname=self.host,
            port=self.port
        )
        self.controller.start()
        logger.info(f"SMTP server started on {self.host}:{self.port}")
        
        # Keep the server running
        while True:
            await asyncio.sleep(3600)  # Sleep for an hour
    
    def stop(self) -> None:
        """Stop the SMTP server"""
        if self.controller:
            self.controller.stop()
            logger.info("SMTP server stopped")

async def main():
    """Main entry point for the application"""
    # Get configuration from environment variables
    smtp_host = os.environ.get('SMTP_HOST', '0.0.0.0')
    smtp_port = int(os.environ.get('SMTP_PORT', 25))
    webhook_url = os.environ.get('WEBHOOK_URL')
    
    if not webhook_url:
        logger.error("WEBHOOK_URL environment variable is required")
        return
    
    # Create and start the server
    server = SMTPWebhookServer(
        host=smtp_host,
        port=smtp_port,
        webhook_url=webhook_url
    )
    
    try:
        logger.info(f"Starting SMTP webhook forwarder on {smtp_host}:{smtp_port}")
        await server.start()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {str(e)}", exc_info=True)
    finally:
        server.stop()

if __name__ == "__main__":
    asyncio.run(main())