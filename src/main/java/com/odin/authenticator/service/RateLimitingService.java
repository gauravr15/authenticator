package com.odin.authenticator.service;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class RateLimitingService {

	 @Value("${ip.rate.limit}")
	    private long requestLimit; // Set as 2 in properties 

	    @Value("${ip.rate.limit.duration}")
	    private long requestLimitDuration; // Set as 1 minute in properties

	    private final ConcurrentHashMap<String, List<Long>> requestTimestamps = new ConcurrentHashMap<>();

	    public boolean allowRequest(String ipAddress) {
	        long currentTime = System.currentTimeMillis();

	        // Initialize the list if it does not exist for the IP address
	        requestTimestamps.putIfAbsent(ipAddress, new LinkedList<>());
	        List<Long> timestamps = requestTimestamps.get(ipAddress);

	        // Remove timestamps that are older than the rate limit duration
	        synchronized (timestamps) {
	            Iterator<Long> iterator = timestamps.iterator();
	            while (iterator.hasNext()) {
	                Long timestamp = iterator.next();
	                if (currentTime - timestamp > TimeUnit.MINUTES.toMillis(requestLimitDuration)) {
	                    iterator.remove();
	                }
	            }

	            // Check if the number of requests in the time window exceeds the limit
	            if (timestamps.size() >= requestLimit) {
	                return false; // Deny request if over the limit
	            }

	            // Add the current timestamp and allow the request
	            timestamps.add(currentTime);
	        }

	        return true;
	    }

}
