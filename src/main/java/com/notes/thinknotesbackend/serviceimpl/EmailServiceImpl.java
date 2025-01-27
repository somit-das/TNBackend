package com.notes.thinknotesbackend.serviceimpl;

import com.notes.thinknotesbackend.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    @Autowired
    private JavaMailSender javaMailSender;

    @Override
    public void sendPasswordResetEmail(String username, String toemail, String resetUrl) {

//        SimpleMailMessage message = new SimpleMailMessage();
//        message.setTo(toemail);
//        message.setSubject("Password Reset Request");
//        message.setText("Clink the link to reset your password: " + resetUrl);
//        javaMailSender.send(message);
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();

        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
            helper.setTo(toemail);
            helper.setSubject("Password Reset Request");
            String htmlContent = "<!DOCTYPE html>\n" +
                    "<html lang=\"en\">\n" +
                    "\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>Password Request</title>\n" +
                    "    <style>\n" +
                    "        body {\n" +
                    "            font-family: Arial, sans-serif;\n" +
                    "            background-color: #f4f4f4;\n" +
                    "            margin: 0;\n" +
                    "            padding: 20px;\n" +
                    "            display: flex;\n" +
                    "            justify-content: center;\n" +
                    "            align-items: center;\n" +
                    "        }\n" +
                    "        .email-container {\n" +
                    "            background-color: #ffffff;\n" +
                    "            border-radius: 8px;\n" +
                    "            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\n" +
                    "            max-width: 600px;\n" +
                    "            width: 100%;\n" +
                    "            padding: 20px;\n" +
                    "        }\n" +
                    "        .header {\n" +
                    "            text-align: center;\n" +
                    "            padding-bottom: 20px;\n" +
                    "            border-bottom: 1px solid #ddd;\n" +
                    "        }\n" +
                    "        .header h2 {\n" +
                    "            color: #333;\n" +
                    "        }\n" +
                    "        .content {\n" +
                    "            margin: 20px 0;\n" +
                    "        }\n" +
                    "        .otp {\n" +
                    "            background-color: #e0f7fa;\n" +
                    "            color: #00796b;\n" +
                    "            font-size: 24px;\n" +
                    "            padding: 10px;\n" +
                    "            text-align: center;\n" +
                    "            border-radius: 5px;\n" +
                    "            margin: 20px 0;\n" +
                    "        }\n" +
                    "        .footer {\n" +
                    "            text-align: center;\n" +
                    "            color: #555;\n" +
                    "            margin-top: 20px;\n" +
                    "            font-size: 14px;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "\n" +
                    "<body>\n" +
                    "    <div class=\"email-container\">\n" +
                    "        <div class=\"header\">\n" +
                    "            <h2>Welcome to ThinkNotes</h2>\n" +
                    "        </div>\n" +
                    "        <div class=\"content\">\n" +
                    "            <p>Dear "+username+"</p>\n" +
                    "            <p>Here is the Forgot Password Link . Please use the following link to reset your account password :</p>\n" +
                    "            <a href="+resetUrl+">link </a>\n" +
                    "            <p>The reset link is valid for 5 minutes. If you did not request this, please ignore this email.</p>\n" +
                    "        </div>\n" +
                    "        <div class=\"footer\">\n" +
                    "            <p>Best regards,</p>\n" +
                    "            <p>ThinkNotes Project by SD</p>\n" +
                    "        </div>\n" +
                    "    </div>\n" +
                    "</body>\n" +
                    "\n" +
                    "</html>";
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
        } catch (MailException | MessagingException e) {
            throw new RuntimeException(e.getMessage());

        }

    }
}
