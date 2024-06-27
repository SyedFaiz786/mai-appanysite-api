import nodemailer from 'nodemailer';
import path from 'path';
import fs from 'fs';
const configPath = path.resolve(__dirname, '../../../config/config.json');

let config;

try {
    const rawData = fs.readFileSync(configPath, 'utf-8');
    config = JSON.parse(rawData);
} catch (error) {
    console.error('Failed to load config file:', error);
    throw error;
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: config.development.email.auth.user,
        pass: config.development.email.auth.pass
    }
});

interface EmailResponse {
    success: boolean;
    message: string;
    error?: string;
}

async function sendEmail(to: string, subject: string, text: string): Promise<EmailResponse> {
    const mailOptions = {
        from: config.development.email.auth.user,
        to: to,
        subject: subject,
        text: text
    };

    try {
        console.log(mailOptions);
        await transporter.sendMail(mailOptions);
        return { success: true, message: 'Email sent successfully' };
    } catch (error: any) {
        console.error('Error sending email:', error);
        return { success: false, message: 'Failed to send email', error: error.message };
    }
}

export { sendEmail };
