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
import time
from datetime import datetime
from email.policy import default
from email.utils import parseaddr
from pathlib import Path
import aiohttp  # For async HTTP requests

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from aiosmtpd.smtp import AuthResult, LoginPassword  # For SMTP auth

from dotenv import load_dotenv  # For environment variable support

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('smtp-json-server')


class RateLimiter:
    """Simple token bucket rate limiter for protection against abuse"""
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()
        
    def is_allowed(self, cost=1):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        
        self.allowance += time_passed * (self.rate / self.per)
        if self.allowance > self.rate:
            self.allowance = self.rate
            
        if self.allowance < cost:
            return False
        else:
            self.allowance -= cost
            return True


class SMTPAuthenticator:
    """Handles SMTP authentication"""
    def __init__(self, credentials):
        self.credentials = credentials
        
    async def auth_login_password(self, server, args):
        username, password = args
        if username in self.credentials and self.credentials[username] == password:
            return AuthResult(success=True)
        return AuthResult(success=False)
        
    async def auth_plain(self, server, args):
        auth_data = args
        # Implementation for PLAIN auth mechanism would go here
        # ...
        # For now, return failed authentication
        return AuthResult(success=False)


class EmailToJSONHandler(Message):
    def __init__(self, webhook_url, max_attachment_size=10*1024*1024):
        """
        Initialize the handler with the webhook URL.
        
        Args:
            webhook_url: URL to POST JSON data
            max_attachment_size: Maximum size of attachments in bytes (default: 10MB)
        """
        # Validate webhook URL
        if not webhook_url.startswith(('http://', 'https://')):
            raise ValueError("Webhook URL must start with http:// or https://")
            
        self.webhook_url = webhook_url
        self.max_attachment_size = max_attachment_size
        self.rate_limiter = RateLimiter(10000, 60)  # 10 emails per minute
        
        super().__init__()
    
    async def handle_message(self, message):
        """
        Process received email messages and convert to JSON.
        """
        # Check rate limit
        if not self.rate_limiter.is_allowed():
            logger.warning("Rate limit exceeded, rejecting message")
            return '421 Rate limit exceeded, try again later'
            
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
                # Check attachment size against limit
                if len(payload) > self.max_attachment_size:
                    logger.warning(f"Attachment {filename} exceeds maximum size limit of {self.max_attachment_size} bytes")
                    attachment = {
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'content_id': part.get('Content-ID', ''),
                        'size': len(payload),
                        'error': 'Attachment exceeds size limit'
                    }
                    email_dict['attachments'].append(attachment)
                    return
                
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


async def amain(host, port, webhook_url, auth_credentials=None, max_attachment_size=10*1024*1024):
    """Async main function to run the SMTP server"""
    handler = EmailToJSONHandler(
        webhook_url=webhook_url,
        max_attachment_size=max_attachment_size
    )
    
    controller_kwargs = {
        'handler': handler,
        'hostname': host,
        'port': port,
    }
    
    # Set up authentication if credentials are provided
    if auth_credentials:
        authenticator = SMTPAuthenticator(auth_credentials)
        controller_kwargs['auth_required'] = True
        controller_kwargs['auth_callback'] = authenticator.auth_login_password
    
    controller = Controller(**controller_kwargs)
    
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
                      default=os.environ.get('SMTP_HOST', '0.0.0.0'),  # Default to localhost for security
                      help='Host to bind the SMTP server to (env: SMTP_HOST)')
                      
    parser.add_argument('--port', 
                      type=int, 
                      default=int(os.environ.get('SMTP_PORT', '8025')),
                      help='Port to bind the SMTP server to (env: SMTP_PORT)')
                      
    parser.add_argument('--webhook-url', 
                      default=os.environ.get('WEBHOOK_URL'),
                      help='URL to POST JSON data (env: WEBHOOK_URL)')
                      
    parser.add_argument('--max-attachment-size',
                      type=int,
                      default=int(os.environ.get('MAX_ATTACHMENT_SIZE', str(15*1024*1024))),  # 15MB default
                      help='Maximum attachment size in bytes (env: MAX_ATTACHMENT_SIZE)')
    
    parser.add_argument('--auth-file',
                      default=os.environ.get('AUTH_FILE'),
                      help='Path to JSON file with username:password auth credentials (env: AUTH_FILE)')
    
    args = parser.parse_args()
    
    if not args.webhook_url:
        parser.error("Webhook URL must be specified (--webhook-url or WEBHOOK_URL environment variable)")
    
    # Load authentication credentials if provided
    auth_credentials = None
    if args.auth_file and os.path.exists(args.auth_file):
        try:
            with open(args.auth_file, 'r') as f:
                auth_credentials = json.load(f)
            logger.info(f"Loaded authentication credentials for {len(auth_credentials)} users")
        except Exception as e:
            logger.error(f"Error loading authentication credentials: {e}")
            parser.error(f"Could not load authentication credentials from {args.auth_file}")
    
    asyncio.run(amain(args.host, args.port, args.webhook_url, auth_credentials, args.max_attachment_size))


if __name__ == "__main__":
    main()