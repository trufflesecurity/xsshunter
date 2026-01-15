const nodemailer = require('nodemailer');
const mustache = require('mustache');
const fs = require('fs');

const XSS_PAYLOAD_FIRE_EMAIL_TEMPLATE = fs.readFileSync(
	'./templates/xss_email_template.htm',
	'utf8'
);

async function send_email_notification(xss_payload_fire_data, email) {
    const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT),
            secure: (process.env.SMTP_USE_TLS === "true"),
            auth: {
                user: process.env.SMTP_USERNAME,
                pass: process.env.SMTP_PASSWORD,
            },
        });

	const notification_html_email_body = mustache.render(
		XSS_PAYLOAD_FIRE_EMAIL_TEMPLATE, 
		xss_payload_fire_data
	);

    const fire_location = (!xss_payload_fire_data.encrypted ? xss_payload_fire_data.url : 'With An Encryption Key');

	const msg = {
		from: process.env.SMTP_FROM_EMAIL,
		to: email,
		subject: `[XSS Hunter Express] XSS Payload Fired On ${fire_location}`,
		text: "Only HTML reports are available, please use an email client which supports this.",
		html: notification_html_email_body,
	};

	response = await transporter
	.sendMail(msg)
	.then((info) => {
          console.log("Message sent: %s", info.messageId);
    })
	.catch((error) => {
		console.error(error);
		return false;
	})

	return true;
}

module.exports.send_email_notification = send_email_notification;
