"""
SMTP to JSON Server

This application acts as an SMTP server that receives emails,
converts them to JSON format (including attachments),
and then posts them to a webhook URL.
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
from functools import partial

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

import aiohttp  # Async HTTP client
from dotenv import load_dotenv  # For environment variable support

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('smtp-json-server')


class CustomController(Controller):
    """
    Custom SMTP controller with enhanced error handling and proper async resource management.
    """
    async def start(self):
        """Start the controller using async."""
        self.server = await self._create_server()
        self.server_task = asyncio.create_task(self.server.serve_forever())
        logger.info(f"SMTP server started on {self.hostname}:{self.port}")
        
    async def _create_server(self):
        """Create and return the SMTP server."""
        return await asyncio.start_server(
            self.handler.handle_SMTP,
            host=self.hostname,
            port=self.port
        )
        
    async def stop_server(self):
        """Stop the server properly with async cleanup."""
        if self.server is not None:
            # Close the server
            self.server.close()
            # Wait for the server to close
            await self.server.wait_closed()
            if hasattr(self, 'server_task') and self.server_task:
                try:
                    self.server_task.cancel()
                    try:
                        await self.server_task
                    except asyncio.CancelledError:
                        pass
                except Exception as e:
                    logger.error(f"Error canceling server task: {e}")
            self.server = None
            self.server_task = None
            
    async def stop(self):
        """Properly stop the controller asynchronously."""
        if self.server:
            logger.info("Stopping SMTP server...")
            await self.stop_server()
        logger.info("SMTP server stopped properly.")


class EmailToJSONHandler(Message):
    def __init__(self, webhook_url):
        """
        Initialize the handler with the webhook URL.
        
        Args:
            webhook_url: URL to POST JSON data
        """
        self.webhook_url = webhook_url
        self.session = None  # Will initialize in handle_message
        
        super().__init__()
    
    def email_to_json(self, message):
        """
        Convert email.message.Message to JSON-serializable dict.
        This is a synchronous method as message parsing doesn't need to be async.
        
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
        """Post the JSON to the configured webhook URL using aiohttp"""
        try:
            # Ensure we have an aiohttp session
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession()
            
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
            timeout = aiohttp.ClientTimeout(total=30 if total_size > 50 * 1024 * 1024 else 10)  # 30 seconds for >50MB
            
            # Make the POST request with appropriate timeout
            async with self.session.post(
                self.webhook_url,
                json=email_json,
                headers=headers,
                timeout=timeout,
                raise_for_status=False  # Handle errors manually
            ) as response:
                status_code = response.status
                logger.info(f"Webhook response: {status_code}")
                
                if status_code >= 400:
                    error_text = await response.text()
                    logger.error(f"Webhook error: {error_text}")
                
                return status_code < 400  # Return success status
            
        except asyncio.TimeoutError:
            logger.error(f"Webhook timeout - request took too long")
            return False
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Webhook connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}", exc_info=True)
            return False
    
    async def handle_message(self, message):
        """
        Process received email messages and convert to JSON.
        """
        try:
            logger.info("Received email: %s", message.get('subject', 'No Subject'))
            
            try:
                # Ensure we have an aiohttp session
                if self.session is None or self.session.closed:
                    self.session = aiohttp.ClientSession()
                
                # Run email_to_json in a thread pool to avoid blocking the event loop
                loop = asyncio.get_running_loop()
                email_json = await loop.run_in_executor(None, self.email_to_json, message)
                
                # Send to webhook
                await self._handle_json_output(email_json)
                
                return '250 Message accepted for processing'
            except Exception as e:
                logger.error("Error processing message content: %s", str(e), exc_info=True)
                # Still return success to the client
                return '250 Message accepted but encountered processing errors'
                
        except Exception as e:
            logger.error("Critical error handling message: %s", str(e), exc_info=True)
            return '500 Error processing message'

    async def handle_DATA(self, server, session, envelope):
        """
        Handle incoming SMTP DATA command with proper async handling.
        """
        try:
            message_data = envelope.content
            mail_from = envelope.mail_from
            rcpt_tos = envelope.rcpt_tos
            
            # Use run_in_executor for potentially blocking operations like parsing email
            loop = asyncio.get_running_loop()
            
            # Parse the email message with error handling
            try:
                # Run the message parsing in a separate thread to avoid blocking
                parse_func = partial(email.message_from_bytes, message_data, policy=default)
                message = await loop.run_in_executor(None, parse_func)
                
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
    # Create a shared aiohttp session for the handler to use
    session = aiohttp.ClientSession()
    controller = None
    
    try:
        handler = EmailToJSONHandler(webhook_url=webhook_url)
        handler.session = session  # Use the shared session
        
        controller = CustomController(
            handler,
            hostname=host,
            port=port
        )
        
        # Start the server asynchronously
        await controller.start()
        
        # Keep the server running until interrupted
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
    finally:
        # Cleanup
        try:
            if controller:
                await controller.stop()
        except Exception as e:
            logger.error(f"Error stopping controller: {e}", exc_info=True)
            
        # Close the aiohttp session
        if session and not session.closed:
            await session.close()
            
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