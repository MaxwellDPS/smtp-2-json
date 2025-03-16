"""
SMTP to JSON Server

This application acts as an SMTP server that receives emails,
converts them to JSON format (including attachments),
and then posts them to a webhook URL.

This version uses a queue-based approach with immediate acknowledgment.
"""

import asyncio
import base64
import email
import json
import logging
import os
import sys
import argparse
import time
from datetime import datetime
from email.policy import default
from email.utils import parseaddr
from functools import partial
from pathlib import Path
from queue import Queue
from threading import Thread

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Session, Envelope

import aiohttp  # Async HTTP client
from dotenv import load_dotenv  # For environment variable support

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('smtp-json-server')


class EmailMessage:
    """Simple container for email data to be processed in background."""
    def __init__(self, content, mail_from, rcpt_tos):
        self.content = content
        self.mail_from = mail_from
        self.rcpt_tos = rcpt_tos


class EmailProcessor(Thread):
    """
    Thread for processing emails in the background.
    This allows us to immediately acknowledge receipt to clients.
    """
    def __init__(self, webhook_url):
        super().__init__(daemon=True)
        self.webhook_url = webhook_url
        self.queue = Queue()
        self.running = True
        self.api_key = os.environ.get('API_KEY')
    
    def add_email(self, email_msg):
        """Add an email to the processing queue."""
        self.queue.put(email_msg)
    
    def run(self):
        """Main thread loop - processes emails from the queue."""
        logger.info("Email processor thread started")
        
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Create an aiohttp session at thread start
            session = None
            
            while self.running:
                try:
                    # Get an email from the queue (with timeout to allow for shutdown)
                    try:
                        email_msg = self.queue.get(timeout=1.0)
                    except:
                        continue
                    
                    # Ensure we have a session
                    if session is None:
                        session = aiohttp.ClientSession(loop=loop)
                    
                    start_time = time.time()
                    logger.info("Processing email from %s", email_msg.mail_from)
                    
                    # Process the email and send to webhook
                    try:
                        # Parse the email message
                        message = email.message_from_bytes(email_msg.content, policy=default)
                        
                        # Add envelope data as headers if not present
                        if 'From' not in message:
                            message['From'] = email_msg.mail_from
                        if 'To' not in message:
                            message['To'] = ', '.join(email_msg.rcpt_tos)
                        
                        # Convert to JSON
                        email_json = self.email_to_json(message)
                        
                        # Send to webhook (run in event loop)
                        future = asyncio.run_coroutine_threadsafe(
                            self.send_to_webhook(session, email_json),
                            loop
                        )
                        # Wait for completion with timeout
                        future.result(timeout=60)
                        
                        logger.info("Email processed successfully in %.2f seconds", 
                                   time.time() - start_time)
                    except Exception as e:
                        logger.error("Error processing email: %s", str(e), exc_info=True)
                    
                    # Mark the task as done
                    self.queue.task_done()
                    
                except Exception as e:
                    logger.error("Error in processor thread: %s", str(e), exc_info=True)
        finally:
            # Clean up
            if session is not None and not session.closed:
                loop.run_until_complete(session.close())
            
            loop.close()
            logger.info("Email processor thread stopped")
    
    def stop(self):
        """Stop the processor thread."""
        self.running = False
        self.join()
    
    def email_to_json(self, message):
        """Convert email message to JSON format."""
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
            logger.error(f"Error extracting headers: {e}")
            email_dict['headers'] = {'error': f"Could not extract headers: {str(e)}"}
        
        # Safely extract common headers
        for header in ['subject', 'from', 'to', 'cc', 'date']:
            try:
                email_dict[header] = message.get(header, '')
            except Exception as e:
                logger.error(f"Error extracting {header}: {e}")
                email_dict[header] = f"Error extracting {header}"
        
        # Extract email addresses with error handling
        try:
            email_dict['from_email'] = parseaddr(email_dict['from'])[1]
        except Exception as e:
            logger.error(f"Error parsing from address: {e}")
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
            logger.error(f"Error parsing to addresses: {e}")
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
                    logger.error(f"Error getting content from message: {e}")
                    email_dict['body'][content_type] = f"Error: Could not extract content. {str(e)}"
        except Exception as e:
            logger.error(f"Error processing message body: {e}")
            email_dict['body']['error'] = f"Failed to process message body: {str(e)}"
        
        return email_dict
    
    def _process_part(self, part, email_dict):
        """Process a message part and update the email_dict."""
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
                    logger.error(f"Error getting content from part: {e}")
                    email_dict['body'][content_type] = f"Error: Could not extract content. {str(e)}"
        except Exception as e:
            logger.error(f"Error processing message part: {e}")
            # Add an error entry to the body section
            email_dict['body']['error'] = f"Failed to process part: {str(e)}"
    
    def _add_attachment(self, part, email_dict):
        """Add an attachment to the email_dict."""
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
                logger.error(f"Error processing attachment payload {filename}: {e}")
                attachment = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'error': f"Payload error: {str(e)}"
                }
                email_dict['attachments'].append(attachment)
                
        except Exception as e:
            logger.error(f"Error processing attachment: {e}")
            # Add a placeholder for the errored attachment
            email_dict['attachments'].append({
                'filename': 'unknown_attachment',
                'content_type': 'application/octet-stream',
                'error': f"Processing error: {str(e)}"
            })
    
    async def send_to_webhook(self, session, email_json):
        """Send the email JSON to the webhook URL."""
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'SMTP-JSON-Server/1.0'
            }
            
            # Add optional API key header if configured
            if self.api_key:
                headers['Authorization'] = f"Bearer {self.api_key}"
            
            # Check for any large attachments and handle them appropriately
            total_size = sum(attachment.get('size', 0) for attachment in email_json.get('attachments', []))
            logger.info(f"Total attachment size: {total_size} bytes")
            
            # For extremely large emails, increase timeout 
            timeout = aiohttp.ClientTimeout(total=30 if total_size > 50 * 1024 * 1024 else 10)
            
            # Make the POST request with appropriate timeout
            async with session.post(
                self.webhook_url,
                json=email_json,
                headers=headers,
                timeout=timeout,
                raise_for_status=False
            ) as response:
                status_code = response.status
                logger.info(f"Webhook response: {status_code}")
                
                if status_code >= 400:
                    error_text = await response.text()
                    logger.error(f"Webhook error: {error_text}")
                
                return status_code < 400
                
        except asyncio.TimeoutError:
            logger.error(f"Webhook timeout - request took too long")
            return False
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Webhook connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False


class EmailToJSONHandler:
    """
    A simplified SMTP handler that immediately acknowledges receipt,
    then processes emails in a background thread.
    """
    def __init__(self, webhook_url):
        """Initialize with webhook URL and start the processor thread."""
        self.processor = EmailProcessor(webhook_url)
        self.processor.start()
    
    async def handle_DATA(self, server, session, envelope):
        """
        Handle incoming SMTP DATA command with immediate acknowledgment.
        """
        try:
            # Create an email message object
            email_msg = EmailMessage(
                content=envelope.content,
                mail_from=envelope.mail_from,
                rcpt_tos=envelope.rcpt_tos
            )
            
            # Add to the processing queue and return immediately
            self.processor.add_email(email_msg)
            
            return '250 Message accepted for processing'
            
        except Exception as e:
            logger.error(f"Error handling DATA command: {e}", exc_info=True)
            return '451 Requested action aborted: local error in processing'
    
    async def handle_EHLO(self, server, session, envelope, hostname):
        """Handle EHLO command."""
        session.host_name = hostname
        return '250-AUTH LOGIN PLAIN\n250 SMTPUTF8'
    
    async def handle_MAIL(self, server, session, envelope, address, mail_options=None):
        """Handle MAIL FROM command."""
        if not address:
            return '501 Syntax: MAIL FROM:<address>'
        envelope.mail_from = address
        envelope.mail_options = mail_options
        return '250 OK'
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options=None):
        """Handle RCPT TO command."""
        if not address:
            return '501 Syntax: RCPT TO:<address>'
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options = rcpt_options
        return '250 OK'
    
    def close(self):
        """Cleanup resources."""
        if self.processor:
            self.processor.stop()


class CustomSMTP(SMTP):
    """Custom SMTP server with better error handling."""
    async def smtp_DATA(self, arg):
        """Override the DATA command handler for better error isolation."""
        if not self.envelope.rcpt_tos:
            await self.push('503 Error: need RCPT command')
            return
        if arg:
            await self.push('501 Syntax: DATA')
            return
        await self.push('354 End data with <CR><LF>.<CR><LF>')
        data = []
        num_bytes = 0
        max_size = self.data_size_limit or 33554432  # 32MB default
        while self._is_connected:
            try:
                line = await self._reader.readline()
                if line == b'.\r\n':
                    break
                num_bytes += len(line)
                if num_bytes > max_size:
                    await self.push('552 Error: Too much mail data')
                    self.envelope.content = None
                    return
                # Remove leading dot if present
                if line.startswith(b'.'):
                    line = line[1:]
                data.append(line)
            except Exception as e:
                logger.error(f"Error reading DATA: {e}", exc_info=True)
                # Return a temporary error
                await self.push('451 Error reading DATA: server error')
                return
        
        # Join all the data into the envelope content
        try:
            self.envelope.content = b''.join(data)
        except Exception as e:
            logger.error(f"Error storing envelope content: {e}", exc_info=True)
            await self.push('451 Error processing DATA: server error')
            return
            
        # Call handler with better error handling
        try:
            status = await self._call_handler_hook('DATA')
            await self.push(status)
        except Exception as e:
            logger.error(f"Error in DATA handler: {e}", exc_info=True)
            await self.push('451 Error processing DATA: server error')
    
    async def _call_handler_hook(self, command, *args):
        """Override handler hook with better error handling."""
        try:
            hook = getattr(self.event_handler, f'handle_{command}', None)
            if hook is None:
                return '500 Command not recognized'
            
            return await hook(self, self.session, self.envelope, *args)
        except Exception as e:
            logger.error(f"Error in handler hook {command}: {e}", exc_info=True)
            return '451 Error in server: command handler failed'


class CustomController(Controller):
    """Custom controller that uses our improved SMTP server."""
    def factory(self):
        """Override factory method to use our custom SMTP server."""
        return CustomSMTP(self.handler)
    
    def stop(self):
        """Override stop to also clean up our handler."""
        # Close the handler resources first
        if hasattr(self.handler, 'close'):
            self.handler.close()
            
        # Then stop the controller
        super().stop()


async def amain(host, port, webhook_url):
    """Async main function to run the SMTP server."""
    handler = EmailToJSONHandler(webhook_url=webhook_url)
    controller = None
    
    try:
        controller = CustomController(
            handler,
            hostname=host,
            port=port
        )
        
        controller.start()
        logger.info(f"SMTP server started on {host}:{port}")
        logger.info(f"Webhook URL configured: {webhook_url}")
        
        # Keep the server running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
    finally:
        # Cleanup
        if controller:
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