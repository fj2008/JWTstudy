package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		//매개변수를 다운캐스팅해서 객체를 만들어서 chain에 넘겨줬다.
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		//토큰이 cos가 아닌 우리가 직접 만들어줘야함
		//id,pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
		//요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오면
		//그 넘어온 토큰으로 이 토큰이 내가 만든토큰이 맞는지 검증만 하면 된다..(RSA,HS256방식)
		
		if(req.getMethod().equals("POST")) {
			
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			
			req.setCharacterEncoding("UTF-8");
			if(headerAuth.equals("cos")) {
				chain.doFilter(req, res);
			}else {
				PrintWriter out = res.getWriter();
				out.println("인증 ㄴㄴ");
			}
		}
	}

}
