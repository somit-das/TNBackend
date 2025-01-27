package com.notes.thinknotesbackend.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
public class MailConfig {

    @Value("${spring.mail.host}")
    private String smtpHost;

    @Value("${spring.mail.port}")
    private Integer port;

    @Value("${spring.mail.username}")
    private String username;

    @Value("${spring.mail.password}")
    private String password;// App Password

    @Bean
    JavaMailSender javaMailSender()
    {
        JavaMailSenderImpl jmsi = new JavaMailSenderImpl();

        jmsi.setHost(smtpHost);
        jmsi.setPort(port);
        jmsi.setUsername(username);
        jmsi.setPassword(password);

        Properties props = jmsi.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.debug", "true");

        return jmsi;
    }
}
