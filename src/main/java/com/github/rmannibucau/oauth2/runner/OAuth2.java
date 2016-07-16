package com.github.rmannibucau.oauth2.runner;

import lombok.NoArgsConstructor;
import org.apache.tomee.embedded.Main;

import static lombok.AccessLevel.PRIVATE;

@NoArgsConstructor(access = PRIVATE)
public final class OAuth2 {
    public static void main(final String[] args) {
        Main.main(new String[] { "--as-war", "--single-classloader" });
    }
}
