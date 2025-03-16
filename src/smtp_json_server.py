"""
SMTP to JSON Server

This application acts as an SMTP server that receives emails,
converts them to JSON format (including attachments),
and then outputs them or forwards them.
"""

import asyncio
import base64
import email
import json
import logging
import os
import argparse
from datetime import datetime
from email.policy import default
from email.utils import parseaddr
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

import aiohttp  # For async HTTP requests
from dotenv import load_dotenv  # For environment variable support

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('smtp-json-server')


class EmailToJSONHandler(Message):
    def __init__(self, webhook_url):
        """
        Initialize the handler with the webhook URL.
        
        Args:
            webhook_url: URL to POST JSON data
        """
        self.webhook_url = webhook_url
        
        super().__init__()
    
    async def handle_message(self, message):
        """
        Process received email messages and convert to JSON.
        """
        try:
            logger.info("Received email: %s", message.get('subject', 'No Subject'))
            
            email_json = self.email_to_json(message)
            
            # Handle the JSON according to configured outputs
            await self._handle_json_output(email_json)
            
            return '250 Message accepted for processing'
        except Exception as e:
            logger.error("Error handling message: %s", str(e), exc_info=True)
            return '500 Error processing message'
    
    def email_to_json(self, message):
        """
        Convert email.message.Message to JSON-serializable dict.
        
        Args:
            message: email.message.Message object
            
        Returns:
            dict: JSON-serializable dictionary with email data
        """
        # Basic email metadata
        email_dict = {
            'timestamp': datetime.now().isoformat(),
            'headers': dict(message.items()),
            'subject': message.get('subject', ''),
            'from': message.get('from', ''),
            'to': message.get('to', ''),
            'cc': message.get('cc', ''),
            'date': message.get('date', ''),
            'body': {},
            'attachments': []
        }
        
        # Extract email addresses
        email_dict['from_email'] = parseaddr(email_dict['from'])[1]
        email_dict['to_emails'] = [parseaddr(addr)[1] for addr in email_dict['to'].split(',') if parseaddr(addr)[1]]
        
        # Process body parts and attachments
        if message.is_multipart():
            for part in message.walk():
                self._process_part(part, email_dict)
        else:
            # Single part message
            content_type = message.get_content_type()
            content = message.get_content()
            
            if content_type.startswith('text/'):
                email_dict['body'][content_type] = content
            else:
                # Treat as attachment
                self._add_attachment(message, email_dict)
        
        return email_dict
    
    def _process_part(self, part, email_dict):
        """Process a message part and update the email_dict"""
        content_type = part.get_content_type()
        content_disposition = part.get('Content-Disposition', '')
        
        # Skip container multipart parts
        if content_type.startswith('multipart/'):
            return
        
        # Check if this is an attachment
        if 'attachment' in content_disposition or 'inline' in content_disposition or not content_type.startswith('text/'):
            self._add_attachment(part, email_dict)
        else:
            # This is a body part
            try:
                content = part.get_content()
                email_dict['body'][content_type] = content
            except Exception as e:
                logger.error(f"Error getting content from part: {e}")
                email_dict['body'][content_type] = "Error: Could not extract content"
    
    def _add_attachment(self, part, email_dict):
        """Add an attachment to the email_dict"""
        filename = part.get_filename()
        if not filename:
            # Generate a filename if none exists
            ext = part.get_content_type().split('/')[1] if '/' in part.get_content_type() else 'bin'
            filename = f"attachment-{len(email_dict['attachments'])}.{ext}"
        
        try:
            payload = part.get_payload(decode=True)
            if payload:
                attachment = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'content_id': part.get('Content-ID', ''),
                    'size': len(payload),
                    'content': base64.b64encode(payload).decode('utf-8')
                }
                email_dict['attachments'].append(attachment)
        except Exception as e:
            logger.error(f"Error processing attachment {filename}: {e}")
            attachment = {
                'filename': filename,
                'content_type': part.get_content_type(),
                'error': str(e)
            }
            email_dict['attachments'].append(attachment)
    
    async def _handle_json_output(self, email_json):
        """Post the JSON to the configured webhook URL"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'SMTP-JSON-Server/1.0'
            }
            
            # Add optional API key header if configured
            api_key = os.environ.get('API_KEY')
            if api_key:
                headers['Authorization'] = f"Bearer {api_key}"
                logger.info("Using API key for webhook authentication")  # Don't log the actual key
            
            # Use aiohttp for asynchronous HTTP requests
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=email_json,
                    headers=headers,
                    timeout=10  # Add timeout for better reliability
                ) as response:
                    status_code = response.status
                    logger.info(f"Webhook response: {status_code}")
                    
                    if status_code >= 400:
                        error_text = await response.text()
                        logger.error(f"Webhook error: {error_text}")
                    
                    return status_code < 400  # Return success status
            
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False

    async def handle_DATA(self, server, session, envelope):
        """
        Handle incoming SMTP DATA command.
        """
        message_data = envelope.content
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        
        message = email.message_from_bytes(message_data, policy=default)
        # Add envelope data as headers if not present
        if 'From' not in message:
            message['From'] = mail_from
        if 'To' not in message:
            message['To'] = ', '.join(rcpt_tos)
        
        return await self.handle_message(message)


async def amain(host, port, webhook_url):
    """Async main function to run the SMTP server"""
    handler = EmailToJSONHandler(webhook_url=webhook_url)
    
    controller = Controller(
        handler,
        hostname=host,
        port=port
    )
    
    controller.start()
    logger.info(f"SMTP server started on {host}:{port}")
    logger.info(f"Webhook URL configured: {webhook_url}")
    
    try:
        # Keep the server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    finally:
        controller.stop()
        logger.info("SMTP server stopped")


def main():
    """
    Main entry point with configuration from environment variables
    and command-line arguments
    """
    # Load environment variables from .env file if present
    load_dotenv()
    
    parser = argparse.ArgumentParser(description='SMTP server that converts emails to JSON and POSTs to a webhook')
    
    # Configuration can come from environment variables or command-line
    parser.add_argument('--host', 
                      default=os.environ.get('SMTP_HOST', '0.0.0.0'),
                      help='Host to bind the SMTP server to (env: SMTP_HOST)')
                      
    parser.add_argument('--port', 
                      type=int, 
                      default=int(os.environ.get('SMTP_PORT', '8025')),
                      help='Port to bind the SMTP server to (env: SMTP_PORT)')
                      
    parser.add_argument('--webhook-url', 
                      default=os.environ.get('WEBHOOK_URL'),
                      help='URL to POST JSON data (env: WEBHOOK_URL)')
    
    args = parser.parse_args()
    
    if not args.webhook_url:
        parser.error("Webhook URL must be specified (--webhook-url or WEBHOOK_URL environment variable)")
    
    asyncio.run(amain(args.host, args.port, args.webhook_url))


if __name__ == "__main__":
    main()