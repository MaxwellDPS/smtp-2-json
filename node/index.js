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
  disabledCommands: ['STARTTLS'], // Disable TLS for simplicity
  authOptional: true,             // Allow anonymous connections
  
  // Handle incoming mail
  onData(stream, session, callback) {
    let mailData = '';
    
    stream.on('data', (chunk) => {
      mailData += chunk;
    });
    
    stream.on('end', async () => {
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
          attachments: []
        };
        
        // Process attachments if any
        if (parsedMail.attachments && parsedMail.attachments.length > 0) {
          emailData.attachments = parsedMail.attachments.map(attachment => ({
            filename: attachment.filename,
            contentType: attachment.contentType,
            contentDisposition: attachment.contentDisposition,
            content: attachment.content.toString('base64')
          }));
        }
        
        // Send the data to the webhook
        console.log(`Forwarding email from ${emailData.from?.text} to webhook`);
        await axios.post(WEBHOOK_URL, emailData, {
          headers: {
            'Content-Type': 'application/json'
          }
        });
        
        console.log('Email forwarded successfully');
        callback();
      } catch (error) {
        console.error('Error processing email:', error.message);
        callback(new Error('Error processing email'));
      }
    });
    
    stream.on('error', (error) => {
      console.error('Stream error:', error.message);
      callback(new Error('Stream error'));
    });
  }
});

// Start the server
server.listen(SMTP_PORT, SMTP_HOST, () => {
  console.log(`SMTP server running at ${SMTP_HOST}:${SMTP_PORT}`);
  console.log(`Emails will be forwarded to ${WEBHOOK_URL}`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('SMTP server error:', error.message);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down SMTP server...');
  server.close(() => {
    console.log('SMTP server shut down successfully');
    process.exit(0);
  });
});