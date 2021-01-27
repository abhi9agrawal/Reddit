package com.example.springredditclone.model;

import java.time.Instant;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class User {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long userId ;
	
	@NotBlank(message = "Username is required field")
	private String username;
	
	@NotBlank(message = "Password is required field")
	private String password;
	
	@NotEmpty(message = "Email is required field")
	private String email;
	
	private Instant createdDate ;
	
    private boolean enabled ;

}
