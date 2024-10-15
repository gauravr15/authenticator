package com.odin.authenticator.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.odin.authenticator.entity.ApiRequestResponseLogger;

@Repository
public interface ApiRequestResponseLoggerRepository extends JpaRepository<ApiRequestResponseLogger, Long>{

}
