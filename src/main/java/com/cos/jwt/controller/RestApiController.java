package com.cos.jwt.controller;


import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.config.SecurityConfig;
import com.cos.jwt.jwt.JWTTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@RestController
@Slf4j
public class RestApiController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final JWTTokenProvider jwtTokenProvider;
	private final SecurityConfig securityConfig;

	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}

	@GetMapping("/")
	public String home1(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		log.info("TEST : {}", authorization);
		return "<h1>home</h1>";
	}
	
	@PostMapping("token")
	public String token() {
		return "<h1>token</h1>";
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return"회원가입완료";
	}

	@PostMapping("auth/login")
	public ResponseEntity<?> userLogin(@RequestBody LoginRequestDto LoginRequestDto, HttpServletResponse response) {
		User user = userRepository.findByUsername(LoginRequestDto.getUsername());
		log.info("나실행되마");
		if (!securityConfig.passwordEncoder().matches(LoginRequestDto.getPassword(), user.getPassword())) {
			throw new IllegalArgumentException("잘못된 비밀번호입니다.");
		}
		String token = jwtTokenProvider.createToken(user.getUsername(), user.getRoleList());
		response.addHeader("Authorization","Bearer " + token);
		return ResponseEntity.ok(token);
	}

	//user권한만 접근가능
	@GetMapping("/api/v1/user")
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		log.info("TEST DATA : {}" , principalDetails.toString());
		return "user";
	}
	//manager,admin권한만 접근가능
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	//admin권한만 접근가능
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
	
	
}

@Getter
@Setter
class LoginRequestDto {
	private String username;
	private String password;
}
