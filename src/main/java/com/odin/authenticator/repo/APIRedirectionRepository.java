package com.odin.authenticator.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.odin.authenticator.entity.APIRedirection;

public interface APIRedirectionRepository extends JpaRepository<APIRedirection, Long>{

}
