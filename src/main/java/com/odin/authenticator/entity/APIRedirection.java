package com.odin.authenticator.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "api_redirection")
@Getter
@Setter
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class APIRedirection {
	
	@Id
	@Column(name = "id")
	private Long id;
	
	@Column(name = "prefix")
	private String prefix;
	
	@Column(name = "base_url")
	private String baseUrl;
}
