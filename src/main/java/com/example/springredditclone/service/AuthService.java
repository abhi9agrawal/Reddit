package com.example.springredditclone.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.springredditclone.dto.AuthenticationResponse;
import com.example.springredditclone.dto.LoginRequest;
import com.example.springredditclone.dto.RefreshTokenRequest;
import com.example.springredditclone.dto.RegisterRequest;
import com.example.springredditclone.exception.SpringRedditException;
import com.example.springredditclone.model.NotificationEmail;
import com.example.springredditclone.model.User;
import com.example.springredditclone.model.VerificationToken;
import com.example.springredditclone.repository.UserRepository;
import com.example.springredditclone.repository.VerificationTokenRepository;
import com.example.springredditclone.security.JwtProvider;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
@Transactional
public class AuthService {
	
	//Recommended to use constructor injection rather than field injection
	private final PasswordEncoder passwordEncoder ;
	
	private  final UserRepository userRepository ;
	
	private final VerificationTokenRepository verificationTokenRepository ;
	
	private final MailService mailService ;
	
	private final AuthenticationManager authenticationManager ;
	
	private final JwtProvider jwtProvider ;
	
	private final RefreshTokenService refreshTokenSevice ;
	
	@Transactional
	public void SignUp(RegisterRequest registerRequest) {
		User user = new User();
		user.setUsername(registerRequest.getUsername());
		user.setEmail(registerRequest.getEmail());
		user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		user.setCreatedDate(Instant.now());
		user.setEnabled(false);
        		
		userRepository.save(user);
		
		String token = generateVerificationToken(user);
		
		mailService.SendMail(new NotificationEmail("Please activate your account" , user.getEmail(), "Thank You for signing up to Reddit. " +
		"Please click on below URL to activate your account. " + "http://localhost:8080/api/auth/accountVerification/" + token));
		
	}

	private String generateVerificationToken(User user) {
		String token = UUID.randomUUID().toString() ; 
		VerificationToken verificationToken = new VerificationToken();
		verificationToken.setToken(token);
		verificationToken.setUser(user);
		
		verificationTokenRepository.save(verificationToken) ;
		
		return token ;
		
	}
	
	public void verifyAccount(String token) {
		Optional<VerificationToken> verificationToken = verificationTokenRepository.findByToken(token) ;
		verificationToken.orElseThrow(() -> new SpringRedditException("Invalid Token")) ;
		fetchUserAndEnable(verificationToken.get());
	}
	
	@Transactional(readOnly = true)
	public User getCurrentUser() {
		org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) SecurityContextHolder
				.getContext().getAuthentication().getPrincipal() ;
		
		return userRepository.findByUsername(principal.getUsername())
				.orElseThrow(() -> new UsernameNotFoundException("Username not found for : " + principal.getUsername())) ;
	}


	@Transactional
	private void fetchUserAndEnable(VerificationToken verificationToken) {
		String username = verificationToken.getUser().getUsername() ;
		User user = userRepository.findByUsername(username).orElseThrow(() -> new SpringRedditException("User not found with username" + username));
		user.setEnabled(true);
		userRepository.save(user) ;
	}
	
	public AuthenticationResponse login(LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())) ;
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String token = jwtProvider.generateToken(authentication) ;
		return  AuthenticationResponse.builder()
				.authenticationToken(token)
				.refreshToken(refreshTokenSevice.generateRefreshToken().getToken())
				.expiresAt(Instant.now().plusMillis(jwtProvider.getJwtExpirationInMillis()))
				.username(loginRequest.getUsername())
				.build();				
	}
	
	public AuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
		refreshTokenSevice.validateRefreshToken(refreshTokenRequest.getRefreshToken());
		String token = jwtProvider.generateTokenWithUsername(refreshTokenRequest.getUsername()) ;
		return AuthenticationResponse.builder()
				   .authenticationToken(token)
				   .refreshToken(refreshTokenRequest.getRefreshToken())
				   .expiresAt(Instant.now().plusMillis(jwtProvider.getJwtExpirationInMillis()))
				   .username(refreshTokenRequest.getUsername())
				   .build() ;
	}
	
	public boolean isLoggedIn() {
		Authentication authentication = new SecurityContextHolder().getContext().getAuthentication() ;
		return !(authentication instanceof AnonymousAuthenticationToken && authentication.isAuthenticated()) ;
	}

}
