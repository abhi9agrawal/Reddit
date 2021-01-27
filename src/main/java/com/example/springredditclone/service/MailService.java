package com.example.springredditclone.service;

import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.example.springredditclone.exception.SpringRedditException;
import com.example.springredditclone.model.NotificationEmail;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Slf4j
public class MailService {

	private final JavaMailSender javaMailSender ;
	
	private final MailContentBuilder mailContentBuilder ;

	@Async
	public void SendMail(NotificationEmail notificationEmail) {
		
		MimeMessagePreparator messagePreparator = mimeMessage -> {
			
			MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
			messageHelper.setFrom("springreddit@email.com");
			messageHelper.setTo(notificationEmail.getRecipient());
			messageHelper.setSubject(notificationEmail.getSubject());
			messageHelper.setText(mailContentBuilder.build(notificationEmail.getBody()));
		};
		
		try {
			javaMailSender.send(messagePreparator);
			log.info("Activation Mail Sent !!") ;
		}
		
		catch(MailException e) {
            log.error("Exception occurred when sending mail", e);
			throw new SpringRedditException("Exception occured while sending mail to " + notificationEmail.getRecipient(), e) ;
		}
				
		
	}
}