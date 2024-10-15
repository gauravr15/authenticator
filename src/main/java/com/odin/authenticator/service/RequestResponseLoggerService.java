package com.odin.authenticator.service;

import java.sql.Timestamp;

import javax.servlet.http.HttpServletRequest;

import org.hibernate.annotations.CreationTimestamp;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.entity.ApiRequestResponseLogger;
import com.odin.authenticator.repo.ApiRequestResponseLoggerRepository;

@Component
public class RequestResponseLoggerService {

	@Autowired
	private ApiRequestResponseLoggerRepository reqRespRepo;

	@CreationTimestamp
	private Timestamp currentTime;

	public ApiRequestResponseLogger setRequestResponseData(HttpServletRequest httpRequest, String requestBody) {
		ApiRequestResponseLogger request = ApiRequestResponseLogger.builder()
				.correlationId(MDC.get(ApplicationConstants.CORRELATION_ID_HEADER_NAME))
				.deviceId(httpRequest.getHeader("deviceId")).requestBody(requestBody).requestTimestamp(currentTime)
				.requestMethod(httpRequest.getMethod()).apiUrl(httpRequest.getRequestURL().toString())
				.requestBody(requestBody).build();
		reqRespRepo.save(request);
		return request;
	}

	public void updateRequestResponseData(ApiRequestResponseLogger request, String backendResponse) {
		request.setResponseTimestamp(currentTime);
		request.setResponseBody(backendResponse);
		reqRespRepo.save(request);
		MDC.get(ApplicationConstants.CORRELATION_ID_HEADER_NAME);
	}

}
