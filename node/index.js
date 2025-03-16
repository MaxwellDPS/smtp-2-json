// SMTP to Webhook Forwarder
// This app acts as an SMTP server and forwards received emails to a webhook as JSON

// Required dependencies
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const axios = require('axios');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Configuration from environment variables
const SMTP_HOST = process.env.SMTP_HOST || '0.0.0.0';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '25', 10);
const WEBHOOK_URL = process.env.WEBHOOK_URL;

if (!WEBHOOK_URL) {
  console.error('Error: WEBHOOK_URL environment variable is required');
  process.exit(1);
}

// Create the SMTP server
const server = new SMTPServer({
  secure: false,
  disabledCommands: ['AUTH', 'STARTTLS'], // Disable authentication and TLS completely
  authOptional: true,             // This is redundant but kept for clarity
  
  // Connection logging
  onConnect(session, callback) {
    const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
    console.log(`${new Date().toISOString()} - Connection established ${clientInfo}`);
    callback(); // Accept the connection
  },
  
  onClose(session) {
    const clientInfo = session.remoteAddress ? `[${session.remoteAddress}:${session.remotePort}]` : '[Unknown client]';
    console.log(`${new Date().toISOString()} - Connection closed ${clientInfo}`);
  },
  
  // Log auth attempts even though auth is disabled
  onAuth(auth, session, callback) {
    const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
    console.log(`${new Date().toISOString()} - Auth attempt from ${clientInfo} user=${auth.username}`);
    callback(new Error('Authentication disabled'));
  },
  
  // Log mail from events
  onMailFrom(address, session, callback) {
    const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
    console.log(`${new Date().toISOString()} - MAIL FROM: ${address.address} ${clientInfo}`);
    callback();
  },
  
  // Log recipient events
  onRcptTo(address, session, callback) {
    const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
    console.log(`${new Date().toISOString()} - RCPT TO: ${address.address} ${clientInfo}`);
    callback();
  },
  
  // Handle incoming mail
  onData(stream, session, callback) {
    const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
    console.log(`${new Date().toISOString()} - Message data transmission started ${clientInfo}`);
    
    let mailData = '';
    let messageSize = 0;
    
    stream.on('data', (chunk) => {
      mailData += chunk;
      messageSize += chunk.length;
    });
    
    stream.on('end', async () => {
      const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
      console.log(`${new Date().toISOString()} - Message data transmission complete ${clientInfo} - Size: ${messageSize} bytes`);
      
      try {
        // Parse the email
        const parsedMail = await simpleParser(mailData);
        
        // Prepare JSON data for webhook
        const emailData = {
          from: parsedMail.from,
          to: parsedMail.to,
          cc: parsedMail.cc,
          subject: parsedMail.subject,
          text: parsedMail.text,
          html: parsedMail.html,
          date: parsedMail.date,
          headers: parsedMail.headerLines.map(header => ({
            key: header.key,
            value: header.line
          })),
          attachments: [],
          messageId: parsedMail.messageId
        };
        
        // Process attachments if any
        if (parsedMail.attachments && parsedMail.attachments.length > 0) {
          console.log(`${new Date().toISOString()} - Processing ${parsedMail.attachments.length} attachments ${clientInfo}`);
          emailData.attachments = parsedMail.attachments.map(attachment => ({
            filename: attachment.filename,
            contentType: attachment.contentType,
            contentDisposition: attachment.contentDisposition,
            content: attachment.content.toString('base64')
          }));
        }
        
        // Log email details
        console.log(`${new Date().toISOString()} - Message details ${clientInfo}:
  Message-ID: ${parsedMail.messageId || 'N/A'}
  From: ${emailData.from?.text || 'N/A'}
  To: ${emailData.to?.text || 'N/A'}
  Subject: ${emailData.subject || 'N/A'}
  Attachments: ${emailData.attachments.length}
`);
        
        // Send the data to the webhook
        console.log(`${new Date().toISOString()} - Forwarding email to webhook ${WEBHOOK_URL}`);
        try {
          const response = await axios.post(WEBHOOK_URL, emailData, {
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          console.log(`${new Date().toISOString()} - Email forwarded successfully - Status: ${response.status}`);
          callback();
        } catch (webhookError) {
          console.error(`${new Date().toISOString()} - Webhook error:`, webhookError.message);
          console.error(`${new Date().toISOString()} - Webhook response:`, webhookError.response?.data);
          // We still mark the SMTP transaction as successful even if webhook fails
          callback();
        }
      } catch (error) {
        console.error(`${new Date().toISOString()} - Error processing email:`, error.message);
        callback(new Error('Error processing email'));
      }
    });
    
    stream.on('error', (error) => {
      const clientInfo = `[${session.remoteAddress}:${session.remotePort}]`;
      console.error(`${new Date().toISOString()} - Stream error ${clientInfo}:`, error.message);
      callback(new Error('Stream error'));
    });
  }
});

// Start the server
server.listen(SMTP_PORT, SMTP_HOST, () => {
  console.log(`${new Date().toISOString()} - SMTP server started and listening at ${SMTP_HOST}:${SMTP_PORT}`);
  console.log(`${new Date().toISOString()} - Emails will be forwarded to ${WEBHOOK_URL}`);
  console.log(`${new Date().toISOString()} - Authentication is disabled`);
});

// Handle server errors
server.on('error', (error) => {
  console.error(`${new Date().toISOString()} - SMTP server error:`, error.message);
  
  // More specific error handling for common issues
  if (error.code === 'EACCES') {
    console.error(`${new Date().toISOString()} - Permission denied. If using port 25, try running with sudo or use a port above 1024`);
  } else if (error.code === 'EADDRINUSE') {
    console.error(`${new Date().toISOString()} - Port ${SMTP_PORT} is already in use. Try a different port`);
  }
});

// Graceful shutdown
const shutdownHandler = (signal) => {
  console.log(`${new Date().toISOString()} - Received ${signal}. Shutting down SMTP server...`);
  server.close(() => {
    console.log(`${new Date().toISOString()} - SMTP server shut down successfully`);
    process.exit(0);
  });
  
  // Force shutdown after 5 seconds if graceful shutdown fails
  setTimeout(() => {
    console.error(`${new Date().toISOString()} - Forced shutdown after 5s timeout`);
    process.exit(1);
  }, 5000);
};

process.on('SIGTERM', () => shutdownHandler('SIGTERM'));
process.on('SIGINT', () => shutdownHandler('SIGINT'));