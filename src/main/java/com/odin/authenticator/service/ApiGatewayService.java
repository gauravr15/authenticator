package com.odin.authenticator.service;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;
import javax.ws.rs.core.HttpHeaders;
import org.springframework.core.io.Resource;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.constants.ResponseCodes;
import com.odin.authenticator.dto.ResponseDTO;
import com.odin.authenticator.utility.BackendUrlSevice;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class ApiGatewayService {
	
	@Autowired
	private ObjectMapper objectMapper;

    private final BackendUrlSevice backendUrlService;
    private final WebClient webClient;

    private static final String CORRELATION_ID_HEADER_NAME = "X-Correlation-ID";

    public ApiGatewayService(BackendUrlSevice backendUrlService, WebClient.Builder webClientBuilder) {
        this.backendUrlService = backendUrlService;
        this.webClient = webClientBuilder.build();
    }

    /**
     * Modifies the incoming URL based on prefix and makes a REST call using WebClient.
     *
     * @param request The original HttpServletRequest
     * @param requestBody The request body (if applicable)
     * @return The response from the backend service
     */
    public String processAndForwardRequest(HttpServletRequest request, String requestBody) throws Exception {
    	logRequestDetails(request, requestBody); 
        String originalUrl = request.getRequestURL().toString();
        String urlPrefix = ApplicationConstants.CONTEXT_PATH + ApplicationConstants.TRAFFIC;

        // Check if the URL contains the prefix and process the URL modification
        if (originalUrl.contains(urlPrefix)) {
            String[] urlParts = originalUrl.split(urlPrefix);
            if (urlParts.length > 1) {
                String dynamicPart = urlParts[1];  // Part after /traffic

                // Extract the first segment after /traffic to use as the key for lookup
                String[] dynamicUrlParts = dynamicPart.split("/");
                String prefix = dynamicUrlParts.length > 1 ? dynamicUrlParts[1] : null;

                // Get the corresponding base URL from BackendUrlService
                if (prefix != null) {
                    String baseUrl = backendUrlService.getDataByKey(prefix);
                    
                    if (baseUrl != null) {
                        // Construct the new URL
                        URI newUri = UriComponentsBuilder.fromHttpUrl(baseUrl)
                                .path(dynamicPart.replace("/" + prefix + "/", "/"))
                                .build().toUri();

                        // Now make a call to the new URL using WebClient
                        System.out.println("new url is : "+newUri); //-> output is new url is : http://192.168.29.110:8020/media/v1/file/upload
                        return forwardRequestToBackend(request, requestBody, newUri);
                    } else {
                        throw new Exception("Invalid URL prefix, no matching base URL found");
                    }
                }
            }
        }

        throw new Exception("URL does not contain expected prefix");
    }

    /**
     * Makes the actual WebClient call based on the incoming HTTP method (GET, POST, etc.)
     *
     * @param request Original HttpServletRequest
     * @param requestBody Request body for POST/PUT methods
     * @param newUri The modified URI
     * @return The backend service response
     */
    private String forwardRequestToBackend(HttpServletRequest request, String requestBody, URI newUri) throws Exception {
        String method = request.getMethod();
        System.out.println("customer id is : "+ request.getAttribute("customerId"));
        WebClient.ResponseSpec responseSpec;

        // Extract Correlation ID from MDC
        String correlationId = MDC.get(CORRELATION_ID_HEADER_NAME);

        try {
            switch (method.toUpperCase()) {
                case "GET":
                    responseSpec = webClient.get()
                            .uri(newUri)
                            .headers(httpHeaders -> {
                                extractHeaders(request, httpHeaders);
                                httpHeaders.add(CORRELATION_ID_HEADER_NAME, correlationId);  // Add Correlation ID
                            })
                            .retrieve();
                    break;
                case "POST":
                	if (isMultipartRequest(request)) {
                		log.info("Handling multipart POST request.");
                        MultipartBodyBuilder multipartBodyBuilder = new MultipartBodyBuilder();

                        // Log multipart data before forwarding
                        extractMultipartData(request, multipartBodyBuilder);
                        logMultipartData(multipartBodyBuilder);
                        URI cleanUri = new URI(
                        		newUri.getScheme(),
                        		newUri.getAuthority(),
                        		newUri.getPath(),
                        		newUri.getQuery(),
                        		newUri.getFragment()
                            );
                        responseSpec = webClient.post()
                                .uri(cleanUri)
                                .headers(httpHeaders -> {
                                    extractHeaders(request, httpHeaders);  // Forward original headers
                                    httpHeaders.add(CORRELATION_ID_HEADER_NAME, correlationId);  // Add correlation ID
                                })
                                .body(BodyInserters.fromMultipartData(multipartBodyBuilder.build())) // Send multipart data
                                .header("Content-Type", MediaType.MULTIPART_FORM_DATA_VALUE) // Set the content type for multipart form
                                .retrieve();
                    }else {
                        // Handle standard POST request
                        responseSpec = webClient.post()
                                .uri(newUri)
                                .headers(httpHeaders -> {
                                    extractHeaders(request, httpHeaders);
                                    httpHeaders.add(CORRELATION_ID_HEADER_NAME, correlationId);  // Add Correlation ID
                                })
                                .bodyValue(requestBody)
                                .retrieve();
                    }
                    break;
                case "PUT":
                    responseSpec = webClient.put()
                            .uri(newUri)
                            .headers(httpHeaders -> {
                                extractHeaders(request, httpHeaders);
                                httpHeaders.add(CORRELATION_ID_HEADER_NAME, correlationId);  // Add Correlation ID
                            })
                            .bodyValue(requestBody)
                            .retrieve();
                    break;
                case "DELETE":
                    responseSpec = webClient.delete()
                            .uri(newUri)
                            .headers(httpHeaders -> {
                                extractHeaders(request, httpHeaders);
                                httpHeaders.add(CORRELATION_ID_HEADER_NAME, correlationId);  // Add Correlation ID
                            })
                            .retrieve();
                    break;
                default:
                    throw new Exception("Unsupported HTTP method: " + method);
            }

            // Execute the request and return the response as String
            
            String resp = responseSpec.bodyToMono(String.class).block();  // Blocking call, handle asynchronously if needed -> exception while executing this line
         //   System.out.println(responseSpec.bodyToMono(String.class).block());
            
            return resp;

        } catch (Exception e) {
            // Log the exception with correlation ID for traceability
            log.error("Error forwarding request to backend. Correlation ID: {}, Error: {}", correlationId, ExceptionUtils.getStackTrace(e));

            // Create a ResponseDTO with failure information
            ResponseDTO errorResponse = ResponseDTO.builder()
                    .statusCode(ResponseCodes.FAILURE_CODE)
                    .status(ResponseCodes.FAILURE)
                    .message(ApplicationConstants.INTERNAL_SERVER_ERROR)  // Include the actual exception message in the response
                    .build();

            // Serialize ResponseDTO to JSON string and return
            return objectMapper.writeValueAsString(errorResponse);
        }
    }


    // Helper method to copy headers from the original request to the new WebClient request
    private void extractHeaders(HttpServletRequest request, org.springframework.http.HttpHeaders headers) {
        Enumeration<String> headerNames = request.getHeaderNames();  // Get header names as Enumeration
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();  // Extract each header name
            headers.add(headerName.trim().replaceAll(" ", ""), request.getHeader(headerName).trim().replaceAll(" ", ""));  // Add it to the WebClient headers
            System.out.println("Forwarding Header: " + headerName + " = " + request.getHeader(headerName));
        }
        headers.add("X-HTTP-Method-Override", request.getMethod());
        System.out.println("method name is : "+request.getMethod());
    }
    
    private boolean isMultipartRequest(HttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType != null && contentType.toLowerCase().contains("multipart/");
    }

    private void extractMultipartData(HttpServletRequest request, MultipartBodyBuilder multipartBodyBuilder) throws IOException, ServletException {
        Collection<Part> parts = request.getParts();
        for (Part part : parts) {
            String name = part.getName();

            if (name == null || name.isEmpty()) {
                log.warn("Part with empty or null name encountered. Skipping part.");
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

    private void logRequestHeaders(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            log.info("Request Header: {} = {}", headerName, request.getHeader(headerName));
        }
    }

    private void logMultipartData(MultipartBodyBuilder multipartBodyBuilder) {
        multipartBodyBuilder.build().forEach((key, parts) -> {
            parts.forEach(part -> {
                log.info("Multipart Field: {} = {}", key, part);
            });
        });
    }


    // Log request body for standard requests
    private void logRequestBody(String requestBody) {
        log.info("Request Body: {}", requestBody);
    }

    private void logRequestDetails(HttpServletRequest request, String requestBody) {
        // Log headers
        logRequestHeaders(request);
        // Log request body for standard requests
        if (requestBody != null && !requestBody.isEmpty()) {
            logRequestBody(requestBody);
        } else {
            log.info("Request Body is empty or null.");
        }

        // Log multipart data if applicable
        if (isMultipartRequest(request)) {
            log.info("Request is multipart.");
        } else {
            log.info("Request is not multipart.");
        }
    }
}