package com.cos.jwt.config;



import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;

@Configuration
public class FilterConfig {
//security필터 체인에 필터를 거는게 아니라 새로 만들어주는게 더 효율적이다
	
	@Bean
	public FilterRegistrationBean<MyFilter1>filter1(){
		FilterRegistrationBean<MyFilter1>bean = new FilterRegistrationBean<>(new MyFilter1());
			bean.addUrlPatterns("/*");
			bean.setOrder(0);//낮은 번호가 필터중에서 가장 먼저 실행됨.
			return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2>filter2(){
		FilterRegistrationBean<MyFilter2>bean = new FilterRegistrationBean<>(new MyFilter2());
			bean.addUrlPatterns("/*");
			bean.setOrder(1);//낮은 번호가 필터중에서 가장 먼저 실행됨.
			return bean;
	}
}
