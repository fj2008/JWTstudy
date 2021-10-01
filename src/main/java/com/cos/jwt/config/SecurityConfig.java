package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.jwt.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig  extends WebSecurityConfigurerAdapter{

	private final CorsFilter corsFilter;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
				}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(),SecurityContextPersistenceFilter.class);
		//http.addFilter(new MyFilter1())이렇게만 설정을 해주면 하면 오류가 난다.
		//오류가 나는 이유는 securityFilter가 아니기때문.
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		//위와같이 설정하면 session을 사용하지 않고 stateless서버를 만들겠다는 설정이다.
		.and()
		.addFilter(corsFilter)
		.formLogin().disable()//jwt는 form태그 사용하는 로그인이 필요없기때문에 하지않기위해서 disable설정
		.httpBasic().disable()//기본적인 http방식을 쓰지않는다.
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) 
		//이렇게 필터에 등록을 하고 꼭 던져줘야하는 파라메터가 있는데
		//AuthenticationManger를 파라메터로 넘겨줘야한다.AuthenticationManger를 통해서 로그인을 하기때문
		
		.authorizeRequests()//다음과 같이 주소를 건다.
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest()//다른요청은 전부 권한없이 들어갈수 있도록
		.permitAll();
		//form로그인을 disable을 해놨기때문에 우리가 직접 PrincipalDetailsService를
		//실행시켜주는 필터를 만들어야한다.
		
		
		
		
	}
}
