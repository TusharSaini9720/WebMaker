const nodemailer = require("nodemailer");

const sendEmail = async (options) => {
  //1.create a transporter(service that will send the email)
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    }, //and activate less secure app on 

  });      
  console.log("transporter",transporter);
  //2.Define email options
  const mailOptions = {
    from: "Tushar Saini <itsaini9720@gmail.com>",
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  //3.Send the email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
