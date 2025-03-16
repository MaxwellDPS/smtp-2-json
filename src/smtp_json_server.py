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
import sys
import argparse
from datetime import datetime
from email.policy import default
from email.utils import parseaddr
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

import requests  # For webhook functionality
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
            
            try:
                # Increase timeout for webhook requests with large attachments
                email_json = self.email_to_json(message)
                
                # Handle the JSON according to configured outputs
                await self._handle_json_output(email_json)
                
                return '250 Message accepted for processing'
            except Exception as e:
                logger.error("Error processing message content: %s", str(e), exc_info=True)
                # Still return success to the client
                return '250 Message accepted but encountered processing errors'
                
        except Exception as e:
            logger.error("Critical error handling message: %s", str(e), exc_info=True)
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
            'headers': {},
            'subject': '',
            'from': '',
            'to': '',
            'cc': '',
            'date': '',
            'body': {},
            'attachments': []
        }
        
        # Safely extract headers
        try:
            email_dict['headers'] = dict(message.items())
        except Exception as e:
            logger.error(f"Error extracting headers: {e}", exc_info=True)
            email_dict['headers'] = {'error': f"Could not extract headers: {str(e)}"}
        
        # Safely extract common headers
        for header in ['subject', 'from', 'to', 'cc', 'date']:
            try:
                email_dict[header] = message.get(header, '')
            except Exception as e:
                logger.error(f"Error extracting {header}: {e}", exc_info=True)
                email_dict[header] = f"Error extracting {header}"
        
        # Extract email addresses with error handling
        try:
            email_dict['from_email'] = parseaddr(email_dict['from'])[1]
        except Exception as e:
            logger.error(f"Error parsing from address: {e}", exc_info=True)
            email_dict['from_email'] = "parse_error"
            
        try:
            if email_dict['to']:
                email_dict['to_emails'] = [
                    parseaddr(addr)[1] for addr in email_dict['to'].split(',') 
                    if parseaddr(addr)[1]
                ]
            else:
                email_dict['to_emails'] = []
        except Exception as e:
            logger.error(f"Error parsing to addresses: {e}", exc_info=True)
            email_dict['to_emails'] = ["parse_error"]
        
        # Process body parts and attachments
        try:
            if message.is_multipart():
                for part in message.walk():
                    self._process_part(part, email_dict)
            else:
                # Single part message
                content_type = message.get_content_type()
                
                try:
                    content = message.get_content()
                    
                    if content_type.startswith('text/'):
                        if isinstance(content, bytes):
                            content = content.decode('utf-8', errors='replace')
                        email_dict['body'][content_type] = content
                    else:
                        # Treat as attachment
                        self._add_attachment(message, email_dict)
                except Exception as e:
                    logger.error(f"Error getting content from message: {e}", exc_info=True)
                    email_dict['body'][content_type] = f"Error: Could not extract content. {str(e)}"
        except Exception as e:
            logger.error(f"Error processing message body: {e}", exc_info=True)
            email_dict['body']['error'] = f"Failed to process message body: {str(e)}"
        
        return email_dict
    
    def _process_part(self, part, email_dict):
        """Process a message part and update the email_dict with improved error handling"""
        try:
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
                    # Ensure the content is properly decoded and handle encoding errors
                    if isinstance(content, bytes):
                        content = content.decode('utf-8', errors='replace')
                    email_dict['body'][content_type] = content
                except Exception as e:
                    logger.error(f"Error getting content from part: {e}", exc_info=True)
                    email_dict['body'][content_type] = f"Error: Could not extract content. {str(e)}"
        except Exception as e:
            logger.error(f"Error processing message part: {e}", exc_info=True)
            # Add an error entry to the body section
            email_dict['body']['error'] = f"Failed to process part: {str(e)}"
    
    def _add_attachment(self, part, email_dict):
        """Add an attachment to the email_dict with improved error handling"""
        try:
            filename = part.get_filename()
            if not filename:
                # Generate a filename if none exists
                ext = part.get_content_type().split('/')[1] if '/' in part.get_content_type() else 'bin'
                filename = f"attachment-{len(email_dict['attachments'])}.{ext}"
            
            # Get payload with safer error handling
            try:
                payload = part.get_payload(decode=True)
                
                # Handle empty payloads
                if payload is None:
                    logger.warning(f"Empty payload for attachment: {filename}")
                    attachment = {
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'content_id': part.get('Content-ID', ''),
                        'size': 0,
                        'content': ''
                    }
                    email_dict['attachments'].append(attachment)
                    return
                
                # For very large attachments, just include metadata without content
                if len(payload) > 10 * 1024 * 1024:  # 10 MB limit
                    logger.warning(f"Large attachment detected: {filename} ({len(payload)} bytes). Including metadata only.")
                    attachment = {
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'content_id': part.get('Content-ID', ''),
                        'size': len(payload),
                        'content_truncated': True,
                        'content': ''  # Empty content for very large attachments
                    }
                else:
                    # Normal attachment processing
                    attachment = {
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'content_id': part.get('Content-ID', ''),
                        'size': len(payload),
                        'content': base64.b64encode(payload).decode('utf-8', errors='replace')
                    }
                email_dict['attachments'].append(attachment)
                
            except Exception as e:
                logger.error(f"Error processing attachment payload {filename}: {e}", exc_info=True)
                attachment = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'error': f"Payload error: {str(e)}"
                }
                email_dict['attachments'].append(attachment)
                
        except Exception as e:
            logger.error(f"Error processing attachment: {e}", exc_info=True)
            # Add a placeholder for the errored attachment
            email_dict['attachments'].append({
                'filename': 'unknown_attachment',
                'content_type': 'application/octet-stream',
                'error': f"Processing error: {str(e)}"
            })
    
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
            
            # Check for any large attachments and handle them appropriately
            total_size = sum(attachment.get('size', 0) for attachment in email_json.get('attachments', []))
            logger.info(f"Total attachment size: {total_size} bytes")
            
            # For extremely large emails, increase timeout or chunk them 
            timeout = 30 if total_size > 50 * 1024 * 1024 else 10  # 30 seconds for >50MB
            
            # Make the POST request with appropriate timeout
            response = requests.post(
                self.webhook_url,
                json=email_json,
                headers=headers,
                timeout=timeout
            )
            
            logger.info(f"Webhook response: {response.status_code}")
            
            if response.status_code >= 400:
                logger.error(f"Webhook error: {response.text}")
            
            return response.status_code < 400  # Return success status
            
        except requests.exceptions.Timeout:
            logger.error(f"Webhook timeout - request took too long")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Webhook connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}", exc_info=True)
            return False

    async def handle_DATA(self, server, session, envelope):
        """
        Handle incoming SMTP DATA command with improved error handling.
        """
        try:
            message_data = envelope.content
            mail_from = envelope.mail_from
            rcpt_tos = envelope.rcpt_tos
            
            # Parse the email message with error handling
            try:
                message = email.message_from_bytes(message_data, policy=default)
                
                # Add envelope data as headers if not present
                if 'From' not in message:
                    message['From'] = mail_from
                if 'To' not in message:
                    message['To'] = ', '.join(rcpt_tos)
                
                return await self.handle_message(message)
            except Exception as e:
                logger.error(f"Error parsing email message: {e}", exc_info=True)
                # Return success to client but log the error
                return '250 Message received but encountered parsing errors'
                
        except Exception as e:
            logger.error(f"Critical error in handle_DATA: {e}", exc_info=True)
            # Return temporary error so client can retry
            return '451 Requested action aborted: local error in processing'


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
    
    # Configure logging based on environment
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger('smtp-json-server')
    
    # Log startup information
    logger.info("Starting SMTP to JSON Server")
    logger.info(f"Log level set to {log_level}")
    
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
    
    logger.info(f"Configuration: host={args.host}, port={args.port}, webhook={args.webhook_url}")
    
    try:
        asyncio.run(amain(args.host, args.port, args.webhook_url))
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()