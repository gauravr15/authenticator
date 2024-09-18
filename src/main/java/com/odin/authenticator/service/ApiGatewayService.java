package com.odin.authenticator.service;

import java.net.URI;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.utility.BackendUrlSevice;

@Service
public class ApiGatewayService {

    private final BackendUrlSevice backendUrlService;
    private final WebClient webClient;

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
        String originalUrl = request.getRequestURL().toString();
        String urlPrefix = ApplicationConstants.CONTEXT_PATH+ApplicationConstants.TRAFFIC;

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
                                .path(dynamicPart)
                                .build().toUri();

                        // Now make a call to the new URL using WebClient
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
        WebClient.ResponseSpec responseSpec;

        switch (method.toUpperCase()) {
            case "GET":
                responseSpec = webClient.get()
                        .uri(newUri)
                        .headers(httpHeaders -> extractHeaders(request, httpHeaders))
                        .retrieve();
                break;
            case "POST":
                responseSpec = webClient.post()
                        .uri(newUri)
                        .headers(httpHeaders -> extractHeaders(request, httpHeaders))
                        .bodyValue(requestBody)
                        .retrieve();
                break;
            case "PUT":
                responseSpec = webClient.put()
                        .uri(newUri)
                        .headers(httpHeaders -> extractHeaders(request, httpHeaders))
                        .bodyValue(requestBody)
                        .retrieve();
                break;
            case "DELETE":
                responseSpec = webClient.delete()
                        .uri(newUri)
                        .headers(httpHeaders -> extractHeaders(request, httpHeaders))
                        .retrieve();
                break;
            default:
                throw new Exception("Unsupported HTTP method: " + method);
        }

        return responseSpec.bodyToMono(String.class).block();  // Blocking call, handle asynchronously as needed
    }

    // Helper method to copy headers from the original request to the new WebClient request
 // Helper method to copy headers from the original request to the new WebClient request
    private void extractHeaders(HttpServletRequest request, org.springframework.http.HttpHeaders headers) {
        Enumeration<String> headerNames = request.getHeaderNames();  // Get header names as Enumeration
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();  // Extract each header name
            headers.add(headerName, request.getHeader(headerName));  // Add it to the WebClient headers
        }
    }

}
