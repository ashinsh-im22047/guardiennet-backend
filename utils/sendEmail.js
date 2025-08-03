const nodemailer = require('nodemailer');

const sendEmail = async (to, subject, html) => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"GuardianNet" <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
    console.log('📧 Email sent to:', to);
  } catch (error) {
    console.error('❌ Failed to send email:', error.message);
    throw new Error('Email could not be sent');
  }
};

module.exports = sendEmail;
