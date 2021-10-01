package com.cos.jwt.jwt;

import java.io.BufferedReader;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

//스프링 시큐리티에서UsernamePasswordAuthenticationFilter가 있다.
//언제 이필터가 동작을 하냐면
//   /login요청을해서 username.password전송하면(POST)
//UsernamePasswordAuthenticationFilter가 동작을 한다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	// /login요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");

		// 1.username,password를 받아서
		// 이함수의 파라메터 request에 담긴 아이디와 비밀번호를 받아본다

		try {

			// 이렇게만 적으면 user오브젝트에 담아준다.
			ObjectMapper om = new ObjectMapper();// json데이터 파싱해준다.
			User user = om.readValue(request.getInputStream(), User.class);

			System.out.println(user);
			// user오브젝트에 데이터가 들어있으면 우리가 직접 token을 만들어줘야한다.

			UsernamePasswordAuthenticationToken authenticationToken =
			new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

			
			// PrincipalDetailsService의 loadUserByUsername()함수가 실행된 후
			//정상이면 로그인이 됐다는 뜻이니까 authentication이 리턴된다.
			//DB에 있는 username과 password가 일치한다
			
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			// authenticationManager에 토큰을 넣어서 던지면 인증을 해준다.
			// 인증을 해주면 authentication이 받는다.
			// authentication에는 클라이언트의 로그인정보가 담겨져있다.

			// 임시로 리턴을 해줄authentication 을 만들었다
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println(principalDetails.getUser().getUsername());//여기에 값이 있다는것은 로그인이 정상적으로 됐다는것이다.

			//authentication 객체가 session영역에 저장을 해야하고 그 방법은 return해주면된다.
			//굳이 리턴을 하는 이유는 권한관리를 security가 대신 해주기때문에 현리하려고 하는것임
			//굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없다. 근데 단지 권한처리대문에 sesison에 넣어주는것이다.
			return authentication;

		} catch (IOException e) {

			e.printStackTrace();
		}

		return null;

	}
	
	//attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
	//JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임.");
		super.successfulAuthentication(request, response, chain, authResult);
	}
}
