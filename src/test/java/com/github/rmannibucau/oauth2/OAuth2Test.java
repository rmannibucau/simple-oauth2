package com.github.rmannibucau.oauth2;

import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.apache.openejb.testing.RandomPort;
import org.apache.tomee.embedded.junit.TomEEEmbeddedSingleRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import java.net.URL;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

@RunWith(TomEEEmbeddedSingleRunner.class)
public class OAuth2Test {
    @RandomPort("http")
    private URL base;

    @Inject
    private OAuthDataProvider provider;

    @Test
    public void token() {
        final Invocation.Builder request = ClientBuilder.newClient()
                .target(base.toExternalForm())
                .path("api/token")
                .request(MediaType.APPLICATION_JSON_TYPE);

        // get a token
        final ClientAccessToken token = request
                .post(Entity.entity(new Form()
                                .param(OAuthConstants.RESOURCE_OWNER_NAME, "test")
                                .param(OAuthConstants.RESOURCE_OWNER_PASSWORD, "pwd")
                                .param(OAuthConstants.CLIENT_ID, App.CLIENT_ID)
                                .param(OAuthConstants.CLIENT_SECRET, App.CLIENT_SECRET)
                                .param(OAuthConstants.GRANT_TYPE, OAuthConstants.RESOURCE_OWNER_GRANT),
                        MediaType.APPLICATION_FORM_URLENCODED_TYPE), ClientAccessToken.class);
        validateToken(token);

        // refresh the token
        final ClientAccessToken refreshedToken = request.post(Entity.entity(new Form()
                        .param(OAuthConstants.REFRESH_TOKEN, token.getRefreshToken())
                        // .param(OAuthConstants.RESOURCE_OWNER_PASSWORD, "pwd")
                        .param(OAuthConstants.CLIENT_ID, App.CLIENT_ID)
                        .param(OAuthConstants.CLIENT_SECRET, App.CLIENT_SECRET)
                        .param(OAuthConstants.GRANT_TYPE, OAuthConstants.REFRESH_TOKEN_GRANT), MediaType.APPLICATION_FORM_URLENCODED_TYPE),
                ClientAccessToken.class);
        validateToken(refreshedToken);
        validateToken(token); // still valid
    }

    private void validateToken(final ClientAccessToken token) {
        assertNotNull(token.getTokenKey());
        assertNotNull(token.getRefreshToken());

        final ServerAccessToken found = provider.getAccessToken(token.getTokenKey());
        assertNotNull(found);
        assertFalse(OAuthUtils.isExpired(found.getIssuedAt(), 3600L));
    }
}
