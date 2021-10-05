package com.cos.jwt.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

//시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있다.
//권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어있다.
//만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않는다

public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

	private UserRepository userRepository;
	
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	
	}
	//인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 된다.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtheader: "+ jwtHeader);
		
		//header가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		//JWT 토큰을 검증을 해서 정상적인 사용자 인지 확인
		String jwttoken = request.getHeader("Authorization").replace("Bearer","");//이렇게하면 jWT만 추출되게 파싱할수 있다.
		
		//전자서명
		String username =
				JWT.require(Algorithm.HMAC512("cos")).build().verify(jwttoken).getClaim("username").asString();
		
		//서명이 정상적으로 됨
		if(username != null) {
			
			User userEntity = userRepository.findByUsername(username);//정상적으로 select되면 정상적인 사용자
			
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			//jwt토큰을 서명을 통해서 서명이 정상이면
			//임의로 Authentication객체를 만들어주는것이다.그래서 pw를 안넣어줬는데
			//이 객체를 만들어줄 수 있는 근거가 뭐냐면
			//username이 null이 아니기때문이다
			//이미 인증이 완료되었다는뜻이다.
			//세번재 인자는 권한을 알려주는것
			Authentication authentication = 
					new UsernamePasswordAuthenticationToken(principalDetails, null,principalDetails.getAuthorities());
			
			//강제로 시큐리티의 세션에 접근하여 Authentication객체를 저장하는것이다.
			//SecurityContextHolder 시큐리티의 세션영역
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
	}
	
	
}
