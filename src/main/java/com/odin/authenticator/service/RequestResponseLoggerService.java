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


	public ApiRequestResponseLogger setRequestResponseData(HttpServletRequest httpRequest, String requestBody) {
		Timestamp currentTime = new Timestamp(System.currentTimeMillis());

		ApiRequestResponseLogger request = ApiRequestResponseLogger.builder()
				.correlationId(MDC.get(ApplicationConstants.CORRELATION_ID_HEADER_NAME))
				.deviceId(httpRequest.getHeader("deviceId")).requestTimestamp(currentTime)
				.requestMethod(httpRequest.getMethod()).apiUrl(httpRequest.getRequestURL().toString()).build();
		
		if (!request.getApiUrl().contains(ApplicationConstants.IMAGE_SERVICE)) {
			request.setRequestBody(requestBody);
		}
		reqRespRepo.save(request);
		request.setRequestBody(requestBody);
		return request;
	}

	public void updateRequestResponseData(ApiRequestResponseLogger request, String backendResponse) {
		Timestamp currentTime = new Timestamp(System.currentTimeMillis());
		request.setResponseTimestamp(currentTime);
		if (!request.getApiUrl().contains(ApplicationConstants.IMAGE_SERVICE)) {
			request.setResponseBody(backendResponse);
		}
		reqRespRepo.save(request);
		MDC.get(ApplicationConstants.CORRELATION_ID_HEADER_NAME);
	}

}
