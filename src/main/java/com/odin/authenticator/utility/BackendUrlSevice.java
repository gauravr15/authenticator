package com.odin.authenticator.utility;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.odin.authenticator.entity.APIRedirection;
import com.odin.authenticator.repo.APIRedirectionRepository;

@Service
public class BackendUrlSevice {

    @Autowired
    private APIRedirectionRepository apiRepo;  
    
    private static Map<String, String> dataMap = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        List<APIRedirection> allData = apiRepo.findAll();

        for (APIRedirection entity : allData) {
            dataMap.put(entity.getPrefix(), entity.getBaseUrl());
        }

        dataMap = Collections.unmodifiableMap(dataMap);
    }

    public String getDataByKey(String key) {
        return dataMap.get(key);
    }

    public Map<String, String> getAllData() {
        return dataMap;
    }
}
