package com.odin.authenticator.filters;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
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
import javax.servlet.http.Part;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.entity.ApiRequestResponseLogger;
import com.odin.authenticator.service.ApiGatewayService;
import com.odin.authenticator.service.RateLimitingService; // Import RateLimitingService
import com.odin.authenticator.service.RequestResponseLoggerService;
import com.odin.authenticator.utility.BackendUrlSevice;
import com.odin.authenticator.utility.CustomHttpRequestWrapper;
import com.odin.authenticator.utility.EncryptionDecryption;
import com.odin.authenticator.utility.JwtTokenUtil;

import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.fileupload.FileItem;




@Component
public class CustomFilter implements Filter {

    private final EncryptionDecryption encryptionService;
    private final ObjectMapper objectMapper;
    private final ApiGatewayService apiGatewayService;
    private final JwtTokenUtil jwtUtil; 
    private final RestTemplate restTemplate;
    private final RateLimitingService rateLimitingService; // Inject RateLimitingService

    @Value("${is.encryption.enabled:true}")
    private boolean isEncryptionEnabled;

    @Value("${bypass.apis}")
    private List<String> bypassApis;
    
    @Autowired
    private BackendUrlSevice backendUrlSevice;
    
    @Autowired
    private RequestResponseLoggerService reqRespService;

    public CustomFilter(EncryptionDecryption encryptionService, ObjectMapper objectMapper, ApiGatewayService apiGatewayService, JwtTokenUtil jwtUtil, RestTemplate restTemplate, RateLimitingService rateLimitingService) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
        this.apiGatewayService = apiGatewayService;
        this.jwtUtil = jwtUtil; 
        this.restTemplate = restTemplate;
        this.rateLimitingService = rateLimitingService; // Initialize RateLimitingService
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String contentType = request.getContentType();
        boolean isMultipart = contentType != null && contentType.contains("multipart/form-data");
        
        Collection<Part> parts = null;

		try {
			if (isMultipart) {
				// Extract multipart parts to enable resource cleanup later
				parts = httpRequest.getParts();
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

     // CORS Handling
        String origin = httpRequest.getHeader("Origin");
        if (origin != null && isValidOrigin(origin)) {
            httpResponse.setHeader("Access-Control-Allow-Origin", origin);
            httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            httpResponse.setHeader("Access-Control-Allow-Headers",
                    "Content-Type, appLang, requestTimestamp, correlationId, Authorization, deviceId, deviceType, deviceName, userType, customerId, fileType");
            httpResponse.setHeader("Access-Control-Expose-Headers", "X-Correlation-ID, responseTimestamp");
            httpResponse.setHeader("Access-Control-Allow-Credentials", "true");
            httpResponse.setHeader("Access-Control-Max-Age", "3600");
        }

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
        String username = ""; // To hold extracted username
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
        
        // Handle video context path requests
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

        // Rate limiting check (before JWT validation)
        if (!rateLimitingService.allowRequest(httpRequest.getRemoteAddr())) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpResponse.getWriter().write("Too many requests. Please try again later.");
            return;
        }

        // JWT validation for non-bypass APIs
        if (!bypassApis.contains(requestURI.replace(ApplicationConstants.CONTEXT_PATH, "").replace(ApplicationConstants.TRAFFIC, ""))) {
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7); // Extract the token

                // Validate JWT
                
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
		if (!isEncryptionEnabled || (bypassApis
				.contains(requestURI.replace(ApplicationConstants.CONTEXT_PATH + ApplicationConstants.TRAFFIC, ""))
				&& !httpRequest.getMethod().equalsIgnoreCase("CORS"))) {
		     try {
                requestBody = httpRequest.getMethod().equalsIgnoreCase("GET") ? null : null;
                if (httpRequest.getMethod().equalsIgnoreCase("POST")) {
                    String body = readRequestBody(httpRequest);
                    Map<String, Object> requestMap = new HashMap<>();
                    if (httpRequest.getContentType() != null && httpRequest.getContentType().startsWith("multipart/form-data")) {
                        try {
                        	
                        	
                            // Handle multipart request
                        	MultipartBodyBuilder multipartBodyBuilder = new MultipartBodyBuilder();

                            // Log multipart data before forwarding
                            extractMultipartData((HttpServletRequest) request, multipartBodyBuilder);
                            //handleMultipartRequest(httpRequest, httpResponse);
                        } catch (Exception e) {
                            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                            httpResponse.getWriter().write("Error processing multipart request");
                            return;
                        }
					} else {
						requestMap = objectMapper.readValue(body, Map.class);
					}
                    String encryptedRequest = (String) requestMap.get("request");
					if (isEncryptionEnabled) {
						if (encryptedRequest == null) {
							httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							httpResponse.getWriter().write("Missing 'request' field in JSON");
							return;
						}
						try {
							requestBody = encryptionService.decrypt(encryptedRequest, requestTimestamp);
						} catch (Exception e) {
							httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
							httpResponse.getWriter().write("Error decrypting data");
							return;
						}
					}
					else {
						requestBody = body;
					}
                }
				if (!ObjectUtils.isEmpty(username)) {
					httpRequest.setAttribute("customerId", username);
				}
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
                System.out.println(ExceptionUtils.getStackTrace(e));
            } finally {
            	 if (isMultipart && parts != null) {
                     for (Part part : parts) {
                         try {
                             part.delete(); // Explicitly delete temporary files
                         } catch (Exception e) {
                             System.err.println("Error deleting temporary file: " + e.getMessage());
                         }
                     }
                 }
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
        Map<String, Object> requestMap = new HashMap<>();
        if (isEncryptionEnabled && !request.getContentType().startsWith("multipart/form-data")) {
            String body = readRequestBody(httpRequest);
            requestMap = objectMapper.readValue(body, Map.class);
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
        }else if (httpRequest.getContentType() != null && httpRequest.getContentType().startsWith("multipart/form-data")) {
        	try {
            	
            	
                // Handle multipart request
            	MultipartBodyBuilder multipartBodyBuilder = new MultipartBodyBuilder();

                // Log multipart data before forwarding
                extractMultipartData((HttpServletRequest) request, multipartBodyBuilder);
                //handleMultipartRequest(httpRequest, httpResponse);
             // Wrap the modified request into CustomHttpRequestWrapper
              wrappedRequest = null;

                  

            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Error processing multipart request");
                return;
            }
        	}  
        else {
            wrappedRequest = (CustomHttpRequestWrapper) httpRequest;
        }

        // After decryption, always call the service to forward the request
        try {
            if (!httpRequest.getContentType().startsWith("multipart/form-data")) {
            	requestBody = wrappedRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(wrappedRequest);
            }
            
            ApiRequestResponseLogger logger = reqRespService.setRequestResponseData(httpRequest, requestBody);
            String backendResponse = apiGatewayService.processAndForwardRequest(isMultipart ? httpRequest : wrappedRequest, requestBody);
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
        String contentType = request.getContentType();

        // Skip reading the body for multipart requests
        if (contentType != null && contentType.startsWith("multipart/form-data")) {
            return null; // Return null or an empty string, as we won't process the body
        }
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
    	String rangeHeader = httpRequest.getHeader("Range");
        HttpHeaders headers = new HttpHeaders();
        if (rangeHeader != null) {
            headers.set("Range", rangeHeader);
        }

        // Make the call to the video service with the Range header (for partial content)
        ResponseEntity<byte[]> videoResponse = restTemplate.exchange(
            baseVideoServiceUrl, HttpMethod.GET, new org.springframework.http.HttpEntity<>(headers), byte[].class
        );

        // Set all response headers received from the video service
        for (Map.Entry<String, List<String>> header : videoResponse.getHeaders().entrySet()) {
            httpResponse.setHeader(header.getKey(), String.join(",", header.getValue()));
        }

        httpResponse.setContentType("video/mp4");
        httpResponse.setStatus(videoResponse.getStatusCodeValue());
        httpResponse.getOutputStream().write(videoResponse.getBody());
        httpResponse.getOutputStream().flush();
    }
    
    public void handleMultipartRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            MultipartHttpServletRequest multipartRequest = 
                new StandardServletMultipartResolver().resolveMultipart(httpRequest);
            String requestTimestamp = httpRequest.getHeader("requestTimestamp");
            // Extract the encrypted 'request' field
            String encryptedRequest = multipartRequest.getParameter("request");
            if (encryptedRequest == null) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Missing 'request' field in multipart data");
                return;
            }

            // Debug logging for troubleshooting
            System.out.println("Encrypted Request: " + encryptedRequest);

            // Decrypt the 'request' field
            String decryptedJson;
            try {
                // Validate Base64 encoding
                byte[] decodedBytes;
                try {
                    decodedBytes = Base64.getDecoder().decode(encryptedRequest);
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid Base64 string: " + encryptedRequest);
                    httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    httpResponse.getWriter().write("Invalid encrypted data format");
                    return;
                }

                // Log decoded byte length for debugging
                System.out.println("Decoded Bytes Length: " + decodedBytes.length);

                // Decrypt the data
                decryptedJson = encryptionService.decrypt(encryptedRequest, requestTimestamp);
                System.out.println("Decrypted JSON: " + decryptedJson);

            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Decryption failed for encryptedRequest: " + encryptedRequest);
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error decrypting data");
                return;
            }

            // Parse decrypted JSON
            try {
                Map<String, Object> decryptedRequestMap = objectMapper.readValue(decryptedJson, Map.class);
                System.out.println("Parsed Decrypted JSON: " + decryptedRequestMap);

                // Continue processing...
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed to parse decrypted JSON: " + decryptedJson);
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Invalid decrypted JSON format");
            }

        } catch (Exception e) {
            e.printStackTrace();
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            try {
                httpResponse.getWriter().write("Unexpected server error");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }


    private void extractMultipartData(HttpServletRequest request, MultipartBodyBuilder multipartBodyBuilder) throws IOException, ServletException {
        Collection<Part> parts = request.getParts();
        for (Part part : parts) {
            String name = part.getName();

            if (name == null || name.isEmpty()) {
                //log.warn("Part with empty or null name encountered. Skipping part.");
                continue;
            }

            if (part.getContentType() != null) {
                InputStream inputStream = part.getInputStream();
                String contentType = part.getContentType();
                String filename = part.getSubmittedFileName() != null ? part.getSubmittedFileName() : "uploaded-file";

                // Preserve filename for downstream services
                multipartBodyBuilder.part(name, new InputStreamResource(inputStream))
                                    .filename(filename)
                                    .contentType(MediaType.parseMediaType(contentType));
            } else {
                // Add regular form data
                String value = new String(readAllBytes(part.getInputStream()), StandardCharsets.UTF_8);
                multipartBodyBuilder.part(name, value);
            }
        }
    }

    private byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024]; // Read in chunks of 1KB
        int bytesRead;
        while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

}
