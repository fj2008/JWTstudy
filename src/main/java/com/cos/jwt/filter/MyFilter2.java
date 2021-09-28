package com.cos.jwt.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class MyFilter2 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("필터2");
		//다시 필터체인에 넘겨주기 위해서 doFilter를 걸어줬다.
		//이렇게 설정해 주지않으면 이 프로세스가 끝나기 때문이다.
		chain.doFilter(request, response);
		
	}

}
