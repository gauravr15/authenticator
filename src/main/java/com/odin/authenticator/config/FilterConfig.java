package com.odin.authenticator.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import com.odin.authenticator.filters.CustomFilter;

@Configuration
public class FilterConfig {

    @Value("${bypass.apis}")
    private String bypassApis;

    @Value("${encryption.key}")
    private String encryptionKey;
    
    @Bean
    public FilterRegistrationBean<CustomFilter> customFilterRegistration(CustomFilter customFilter) {
        FilterRegistrationBean<CustomFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(customFilter);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
