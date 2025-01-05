package com.odin.authenticator.filters;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.entity.ApiRequestResponseLogger;
import com.odin.authenticator.service.ApiGatewayService;
import com.odin.authenticator.service.RequestResponseLoggerService;
import com.odin.authenticator.utility.BackendUrlSevice;
import com.odin.authenticator.utility.CustomHttpRequestWrapper;
import com.odin.authenticator.utility.EncryptionDecryption;
import com.odin.authenticator.utility.JwtTokenUtil;

@Component
public class CustomFilter implements Filter {

    private final EncryptionDecryption encryptionService;
    private final ObjectMapper objectMapper;
    private final ApiGatewayService apiGatewayService;  // Use the new ApiGatewayService
    private final JwtTokenUtil jwtUtil; // Inject JwtUtil
    private final RestTemplate restTemplate;

    @Value("${is.encryption.enabled:true}")
    private boolean isEncryptionEnabled;

    @Value("${bypass.apis}")
    private List<String> bypassApis;
    
    @Autowired
    private BackendUrlSevice backendUrlSevice;
    
    @Autowired
    private RequestResponseLoggerService reqRespService;

    public CustomFilter(EncryptionDecryption encryptionService, ObjectMapper objectMapper, ApiGatewayService apiGatewayService, JwtTokenUtil jwtUtil, RestTemplate restTemplate) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
        this.apiGatewayService = apiGatewayService;
        this.jwtUtil = jwtUtil; // Initialize JwtUtil
        this.restTemplate = restTemplate;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // CORS Handling
        String origin = httpRequest.getHeader("Origin");
		if (origin != null && isValidOrigin(origin)) {
			httpResponse.setHeader("Access-Control-Allow-Origin", origin);
			httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
			httpResponse.setHeader("Access-Control-Allow-Headers",
					"Content-Type, appLang, requestTimestamp, correlationId, Authorization, deviceId, deviceType, deviceName,userType");
			httpResponse.setHeader("Access-Control-Expose-Headers", "X-Correlation-ID, responseTimestamp");
			httpResponse.setHeader("Access-Control-Allow-Credentials", "true");
			httpResponse.setHeader("Access-Control-Max-Age", "3600");
		}

        // Handle preflight (OPTIONS) requests
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            httpResponse.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        // Generate or extract Correlation ID
        String correlationId = httpRequest.getHeader(ApplicationConstants.CORRELATION_ID_HEADER_NAME);
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }

        // Add correlation ID to MDC for logging
        MDC.put(ApplicationConstants.CORRELATION_ID_HEADER_NAME, correlationId);

        // Add correlation ID to the response header
        httpResponse.setHeader(ApplicationConstants.CORRELATION_ID_HEADER_NAME, correlationId);
        String appLang = httpRequest.getHeader(ApplicationConstants.APP_LANG);
        if(ObjectUtils.isEmpty(appLang)) {
            httpResponse.setHeader(ApplicationConstants.APP_LANG, ApplicationConstants.DEFAULT_LANGUAGE);
        } else {
            httpResponse.setHeader(ApplicationConstants.APP_LANG, appLang);
        }

        String requestTimestamp = httpRequest.getHeader("requestTimestamp");
        String requestURI = httpRequest.getRequestURI();
        String requestBody = null;
        
		if (requestURI.contains(ApplicationConstants.VIDEO_CONTEXT_PATH)) {
			String videoUri = "";
			String originalUrl = httpRequest.getRequestURL().toString();
			String urlPrefix = ApplicationConstants.CONTEXT_PATH + ApplicationConstants.TRAFFIC;

			if (originalUrl.contains(urlPrefix)) {
				String[] urlParts = originalUrl.split(urlPrefix);
				if (urlParts.length > 1) {
					String dynamicPart = urlParts[1];

					String[] dynamicUrlParts = dynamicPart.split("/");
					String prefix = dynamicUrlParts.length > 1 ? dynamicUrlParts[1] : null;

					String baseUrl = backendUrlSevice.getDataByKey(prefix);

					URI newUri = UriComponentsBuilder.fromHttpUrl(baseUrl)
							.path(dynamicPart.replace("/" + prefix + "/", "/")).build().toUri();

					videoUri = newUri.toString();

				}
			}

			forwardVideoRequest(httpRequest, httpResponse, videoUri);
			return; // Exit filter chain as the video service is being handled
		}

        // JWT validation for non-bypass APIs
        System.out.println(requestURI.replace(ApplicationConstants.CONTEXT_PATH, "").replace(ApplicationConstants.TRAFFIC, ""));
		if (!bypassApis.contains(
				requestURI.replace(ApplicationConstants.CONTEXT_PATH, "").replace(ApplicationConstants.TRAFFIC, ""))) {
			  String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7); // Extract the token

                // Validate JWT
                String username; // To hold extracted username
                try {
                    username = jwtUtil.getUsernameFromToken(jwtToken);
                    if (!jwtUtil.validateToken(jwtToken, username)) {
                        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        httpResponse.getWriter().write("Invalid or expired JWT token");
                        return;
                    }
                } catch (Exception e) {
                    httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    httpResponse.getWriter().write("JWT validation failed: " + e.getMessage());
                    return;
                }
            } else {
                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpResponse.getWriter().write("Authorization header missing or invalid");
                return;
            }
        }

        // If encryption is disabled or the API is bypassed, proceed with URL transformation and REST call
		if (!isEncryptionEnabled || bypassApis.contains(requestURI.replace(ApplicationConstants.CONTEXT_PATH, ""))
				&& !httpRequest.getMethod().equalsIgnoreCase("CORS")) {
		    try {
                requestBody = httpRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(httpRequest);
                ApiRequestResponseLogger logger = reqRespService.setRequestResponseData(httpRequest, requestBody);
                String backendResponse = apiGatewayService.processAndForwardRequest(httpRequest, requestBody);
                reqRespService.updateRequestResponseData(logger, backendResponse);
                // Encrypt and send the response
                if (isEncryptionEnabled) {
                    sendEncryptedResponse(httpResponse, backendResponse);
                } else {
                    httpResponse.setContentType("application/json;charset=UTF-8");
                    httpResponse.setCharacterEncoding("UTF-8");
                    httpResponse.setHeader("responseTimestamp", requestTimestamp);

                    // Write the encrypted response
                    httpResponse.getWriter().write(backendResponse);
                }
            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error processing request: " + e.getMessage());
            } finally {
                // Clear MDC after processing
                MDC.clear();
            }
            return;
        }

        // Handle decryption
        if (requestTimestamp == null) {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpResponse.getWriter().write("Missing requestTimestamp header");
            return;
        }

        if ("GET".equalsIgnoreCase(httpRequest.getMethod()) || httpRequest.getContentLength() == 0) {
            chain.doFilter(request, response);
            return;
        }

        CustomHttpRequestWrapper wrappedRequest;
        if (isEncryptionEnabled) {
            String body = readRequestBody(httpRequest);
            Map<String, Object> requestMap = objectMapper.readValue(body, Map.class);
            String encryptedRequest = (String) requestMap.get("request");

            if (encryptedRequest == null) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Missing 'request' field in JSON");
                return;
            }

            String decryptedJson;
            try {
                decryptedJson = encryptionService.decrypt(encryptedRequest, requestTimestamp);
            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error decrypting data");
                return;
            }

            wrappedRequest = new CustomHttpRequestWrapper(httpRequest, decryptedJson);
        } else {
            wrappedRequest = (CustomHttpRequestWrapper) httpRequest;
        }

        // After decryption, always call the service to forward the request
        try {
            requestBody = wrappedRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(wrappedRequest);
            ApiRequestResponseLogger logger = reqRespService.setRequestResponseData(httpRequest, requestBody);
            String backendResponse = apiGatewayService.processAndForwardRequest(wrappedRequest, requestBody);
            reqRespService.updateRequestResponseData(logger, backendResponse);
            // Encrypt and send the response
            if (isEncryptionEnabled) {
                sendEncryptedResponse(httpResponse, backendResponse);
            } else {
                httpResponse.setContentType("application/json;charset=UTF-8");
                httpResponse.setCharacterEncoding("UTF-8");
                httpResponse.setHeader("responseTimestamp", requestTimestamp);

                // Write the encrypted response
                httpResponse.getWriter().write(backendResponse);
            }

        } catch (Exception e) {
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            httpResponse.getWriter().write("Error processing request: " + e.getMessage());
        } finally {
            // Clear MDC after processing
            MDC.clear();
        }
    }

    @Override
    public void destroy() {}

    private String readRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder requestBody = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }
        }
        return requestBody.toString();
    }

    // Encrypt the response and set the current timestamp in the response header
    private void sendEncryptedResponse(HttpServletResponse httpResponse, String backendResponse) throws Exception {
        long currentEpochMillis = Instant.now().toEpochMilli();
        // Encrypt the response
        String encryptedResponse = encryptionService.encrypt(backendResponse, String.valueOf(currentEpochMillis));

        // Create the response structure
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("response", encryptedResponse);
        String jsonResponse = objectMapper.writeValueAsString(responseMap);

        // Set response content type and character encoding
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setHeader("responseTimestamp", String.valueOf(currentEpochMillis));

        // Write the encrypted response
        httpResponse.getWriter().write(jsonResponse);
    }

    // Validate origin. You can add custom logic to restrict specific origins if needed.
    private boolean isValidOrigin(String origin) {
        // Example: allow all origins for simplicity. Customize as needed.
        return true;
    }
    
    private void forwardVideoRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseVideoServiceUrl) throws IOException {
        String videoServiceUrl = baseVideoServiceUrl;

        ResponseEntity<byte[]> videoResponse = restTemplate.exchange(
            videoServiceUrl, HttpMethod.GET, null, byte[].class);

        for (Map.Entry<String, List<String>> header : videoResponse.getHeaders().entrySet()) {
            httpResponse.setHeader(header.getKey(), String.join(",", header.getValue()));
        }

        httpResponse.setContentType("video/mp4");
        httpResponse.getOutputStream().write(videoResponse.getBody());
    }
}
