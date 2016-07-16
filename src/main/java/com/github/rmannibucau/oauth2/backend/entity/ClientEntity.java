package com.github.rmannibucau.oauth2.backend.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Id;

@Getter
@Setter
@Entity
public class ClientEntity {
    @Id
    private String id;
    private String secret;
    private boolean confidential;
    private String application;
    private String webUri;
}
