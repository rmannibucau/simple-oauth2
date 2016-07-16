package com.github.rmannibucau.oauth2.backend.entity;

import lombok.Getter;
import lombok.Setter;
import org.apache.cxf.rs.security.oauth2.common.Client;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Getter
@Setter
@Entity
public class TokenEntity {
    @Id
    private String id;

    @ManyToOne
    private ClientEntity client;

    private String tokenType;
    private String refreshToken;
    private long expiresIn;
    private long issuedAt;
    private String issuer;
    private String grantType;
    private String clientCodeVerifier;
    private String nonce;
    private String responseType;
    private String grantCode;
}
