package com.github.rmannibucau.oauth2.backend;

import com.github.rmannibucau.oauth2.backend.entity.ClientEntity;
import com.github.rmannibucau.oauth2.backend.entity.TokenEntity;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.provider.AbstractOAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.bearer.BearerAccessToken;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;

import javax.enterprise.context.ApplicationScoped;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;
import java.util.List;
import java.util.function.Supplier;

import static java.util.Optional.ofNullable;

@Transactional
@ApplicationScoped
public class JPAOAuthDataProvider extends AbstractOAuthDataProvider {
    @PersistenceContext
    private EntityManager em;

    @Override
    protected boolean isRefreshTokenSupported(final List<String> theScopes) {
        return true;
    }

    @Override
    protected void saveAccessToken(final ServerAccessToken serverToken) {
        em.persist(toEntity(serverToken, new TokenEntity()));
        em.flush();
    }

    @Override
    protected void saveRefreshToken(final ServerAccessToken at, final RefreshToken refreshToken) {
        em.persist(toEntity(refreshToken, new TokenEntity()));
        em.flush();
    }

    @Override
    protected ServerAccessToken revokeAccessToken(final String accessTokenKey) {
        return revoke(accessTokenKey, BearerAccessToken::new);
    }

    @Override
    protected RefreshToken revokeRefreshToken(final String refreshTokenKey) {
        return revoke(refreshTokenKey, RefreshToken::new);
    }

    @Override
    public Client getClient(final String clientId) {
        return ofNullable(em.find(ClientEntity.class, clientId))
                .map(this::toClient)
                .orElse(null);
    }

    @Override
    protected RefreshToken getRefreshToken(final String refreshTokenKey) {
        return find(refreshTokenKey, RefreshToken::new);
    }

    @Override
    public ServerAccessToken getAccessToken(final String accessToken) throws OAuthServiceException {
        return find(accessToken, BearerAccessToken::new);
    }

    @Override
    public Client removeClient(final String clientId) {
        return ofNullable(em.find(ClientEntity.class, clientId))
                .map(e -> {
                    em.remove(e);
                    return e;
                })
                .map(this::toClient)
                .orElse(null);
    }

    @Override
    public void setClient(final Client client) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<Client> getClients(final UserSubject resourceOwner) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ServerAccessToken> getAccessTokens(final Client client, final UserSubject subject) throws OAuthServiceException {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<RefreshToken> getRefreshTokens(final Client client, final UserSubject subject) throws OAuthServiceException {
        throw new UnsupportedOperationException();
    }

    private <T extends ServerAccessToken> T find(final String key, final Supplier<T> provider) {
        return ofNullable(em.find(TokenEntity.class, key))
                .map(serverToken -> toToken(serverToken, provider.get()))
                .orElse(null);
    }

    private <T extends ServerAccessToken> T revoke(final String key, final Supplier<T> provider) {
        return ofNullable(em.find(TokenEntity.class, key))
                .map(e -> {
                    em.remove(e);
                    return e;
                })
                .map(serverToken -> toToken(serverToken, provider.get()))
                .orElse(null);
    }

    private Client toClient(final ClientEntity e) {
        return new Client(e.getId(), e.getSecret(), e.isConfidential(), e.getApplication(), e.getWebUri());
    }

    private TokenEntity toEntity(final ServerAccessToken serverToken, final TokenEntity entity) {
        entity.setId(serverToken.getTokenKey());
        entity.setClient(ofNullable(serverToken.getClient()).map(c -> em.find(ClientEntity.class, c.getClientId())).orElse(null));
        entity.setClientCodeVerifier(serverToken.getClientCodeVerifier());
        entity.setGrantCode(serverToken.getGrantCode());
        entity.setGrantType(serverToken.getGrantType());
        entity.setNonce(serverToken.getNonce());
        entity.setResponseType(serverToken.getResponseType());
        entity.setTokenType(serverToken.getTokenType());
        entity.setRefreshToken(serverToken.getRefreshToken());
        entity.setExpiresIn(serverToken.getExpiresIn());
        entity.setIssuedAt(serverToken.getIssuedAt());
        entity.setIssuer(serverToken.getIssuer());
        
        // this works and stores roles comma separated
	// but causes refresh token invalid_grant
        List<String> roles = serverToken.getSubject().getRoles();
	entity.setRoles(roles.stream().collect(Collectors.joining(",")));
        
        return entity;
    }

    private <T extends ServerAccessToken> T toToken(final TokenEntity tokenEntity, final T serverAccessToken) {
        serverAccessToken.setTokenKey(tokenEntity.getId());
        serverAccessToken.setClient(ofNullable(tokenEntity.getClient()).map(this::toClient).orElse(null));
        serverAccessToken.setClientCodeVerifier(tokenEntity.getClientCodeVerifier());
        serverAccessToken.setGrantCode(tokenEntity.getGrantCode());
        serverAccessToken.setGrantType(tokenEntity.getGrantType());
        serverAccessToken.setNonce(tokenEntity.getNonce());
        serverAccessToken.setResponseType(tokenEntity.getResponseType());
        serverAccessToken.setTokenType(tokenEntity.getTokenType());
        serverAccessToken.setRefreshToken(tokenEntity.getRefreshToken());
        serverAccessToken.setExpiresIn(tokenEntity.getExpiresIn());
        serverAccessToken.setIssuedAt(tokenEntity.getIssuedAt());
        serverAccessToken.setIssuer(tokenEntity.getIssuer());
        
        // causes refresh token invalid_grant
        if (tokenEntity.getRoles() != null) {
		Map<String, String> parameters = new HashMap<>();
		parameters.put("roles", tokenEntity.getRoles());
		serverAccessToken.setParameters(parameters);
	}
        
        return serverAccessToken;
    }
    
    @Override
	protected ServerAccessToken doCreateAccessToken(AccessTokenRegistration atReg) {
		ServerAccessToken at = createNewAccessToken(atReg.getClient(), atReg.getSubject());
		at.setAudiences(atReg.getAudiences());
		at.setGrantType(atReg.getGrantType());
		List<String> theScopes = atReg.getApprovedScope();
		List<OAuthPermission> thePermissions = convertScopeToPermissions(atReg.getClient(), theScopes);
		at.setScopes(thePermissions);
		at.setSubject(atReg.getSubject());
		at.setClientCodeVerifier(atReg.getClientCodeVerifier());
		at.setNonce(atReg.getNonce());
		at.setResponseType(atReg.getResponseType());
		at.setGrantCode(atReg.getGrantCode());
		at.getExtraProperties().putAll(atReg.getExtraProperties());

		// add roles
		List<String> roles = atReg.getSubject().getRoles();
		String rolesString = roles.stream().collect(Collectors.joining(","));
		at.getParameters().put("roles", rolesString);

		if (isUseJwtFormatForAccessTokens()) {
			JwtClaims claims = createJwtAccessToken(at);
			String jose = processJwtAccessToken(claims);
			at.setTokenKey(jose);
		}

		return at;
	}
}
