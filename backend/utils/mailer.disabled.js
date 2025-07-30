// backend/utils/mailer.js

const nodemailer = require('nodemailer');

// 1) Configure transporteur SMTP via tes vars d'env
// Définis dans .env : MAIL_HOST, MAIL_PORT, MAIL_SECURE, MAIL_USER, MAIL_PASS, MAIL_FROM
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: parseInt(process.env.MAIL_PORT, 10),
  secure: process.env.MAIL_SECURE === 'true', // true si port 465, false pour 587
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

/**
 * Envoie à l'utilisateur un lien privé pour consulter sa réponse.
 * @param {string} email – Adresse de destination
 * @param {string} link  – Lien complet (ex. `${APP_BASE_URL}/view/${token}`)
 */
async function sendResponseLink(email, link) {
  const mailOptions = {
    from: process.env.MAIL_FROM, // ex. '"Form-A-Friend" <no-reply@tondomaine.com>'
    to: email,
    subject: 'Votre lien pour consulter vos réponses',
    text: [
      'Bonsoir cher tous,',
      '',
      'Merci d’avoir répondu à mon formulaire mensuel !',
      `Vous pouvez consulter vos réponses ainsi que les miennes en cliquant ici :`,
      link,
      '',
      'La bise,',
      'Irina'
    ].join('\n'),
    html: `
      <p>Bonsoir cher tous,</p>
      <p>Merci d’avoir répondu à mon formulaire mensuel !</p>
      <p>Vous pouvez consulter vos réponses ainsi que les miennes en cliquant ici : <a href="${link}">${link}</a></p>
      <p>La bise,<br/>Irina</p>
    `
  };

  // 2) Envoi
  const info = await transporter.sendMail(mailOptions);
  console.log('Mail envoyé : %s', info.messageId);
  return info;
}

module.exports = { sendResponseLink };
