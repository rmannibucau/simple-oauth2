package com.github.rmannibucau.oauth2.front;

import com.github.rmannibucau.oauth2.backend.JPAOAuthDataProvider;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.grants.owner.JAASResourceOwnerLoginHandler;
import org.apache.cxf.rs.security.oauth2.grants.owner.ResourceOwnerGrantHandler;
import org.apache.cxf.rs.security.oauth2.grants.refresh.RefreshTokenGrantHandler;
import org.apache.cxf.rs.security.oauth2.services.AccessTokenService;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.stream.Stream;

@Path("token")
@RequestScoped
public class TokenResource {
    private final AccessTokenService delegate = new AccessTokenService();

    @Inject
    private JPAOAuthDataProvider provider;

    @PostConstruct
    private void setup() {
        delegate.setDataProvider(provider);
        Stream.of(new ResourceOwnerGrantHandler() {{
                      setDataProvider(provider);
                      setLoginHandler(new JAASResourceOwnerLoginHandler() {{
                          setContextName("oauth2");
                      }});
                  }}, new RefreshTokenGrantHandler() {{
                      setDataProvider(provider);
                  }}
        ).forEach(delegate::setGrantHandler);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response handleTokenRequest(final MultivaluedMap<String, String> params) {
        return delegate.handleTokenRequest(params);
    }

    @Context
    public void setMessageContext(final MessageContext context) {
        delegate.setMessageContext(context);
    }
}
