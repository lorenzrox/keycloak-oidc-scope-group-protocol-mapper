package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

public class OIDCScopeGroupProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    private static final String FULL_PATH = "fullPath";
    private static final String SCOPE = "scope";

    private static final String FULL_PATH_LABEL = "oidc-scope-group-protocol-mapper.full-path.label";
    private static final String FULL_PATH_HELP_TEXT = "oidc-scope-group-protocol-mapper.full-path.tooltip";
    private static final String SCOPE_LABEL = "oidc-scope-group-protocol-mapper.scope.label";
    private static final String SCOPE_HELP_TEXT = "oidc-scope-group-protocol-mapper.scope.tooltip";

    public static final String PROVIDER_ID = "oidc-scope-group-protocol-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty fullPathProperty = new ProviderConfigProperty();
        fullPathProperty.setName(FULL_PATH);
        fullPathProperty.setLabel(FULL_PATH_LABEL);
        fullPathProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullPathProperty.setDefaultValue("true");
        fullPathProperty.setHelpText(FULL_PATH_HELP_TEXT);

        configProperties.add(fullPathProperty);

        ProviderConfigProperty scopeProperty = new ProviderConfigProperty();
        scopeProperty.setName(SCOPE);
        scopeProperty.setLabel(SCOPE_LABEL);
        scopeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        scopeProperty.setDefaultValue("group");
        scopeProperty.setHelpText(SCOPE_HELP_TEXT);

        configProperties.add(scopeProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OIDCScopeGroupProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Scope-based Group Membership";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Map scope to user group membership";
    }

    @Override
    protected void setClaim(IDToken idToken, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String membership = getMembership(mappingModel, userSession, clientSessionCtx);
        if (membership != null) {
            OIDCAttributeMapperHelper.mapClaim(idToken, mappingModel, membership);
        }
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        String membership = getMembership(mappingModel, userSession, clientSessionCtx);
        if (membership != null) {
            OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, mappingModel, membership);
        }
    }

    private static String getMembership(ProtocolMapperModel mappingModel, UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        AuthorizationRequestContext authorizationRequestContext = clientSessionCtx.getAuthorizationRequestContext();
        String scopeName = mappingModel.getConfig().get(SCOPE);
        String groupName = authorizationRequestContext.getAuthorizationDetailEntries()
                .stream()
                .filter(d -> d.getClientScope().getName().equals(scopeName))
                .map(d -> d.getDynamicScopeParam())
                .findFirst().orElse(null);

        if (groupName != null) {
            String membership = userSession.getUser().getGroupsStream()
                    .filter(g -> g.getName().equalsIgnoreCase(groupName))
                    .map(useFullPath(mappingModel)
                            ? ModelToRepresentation::buildGroupPath
                            : GroupModel::getName)
                    .findFirst().orElse(null);
            return membership;
        }

        return null;
    }

    public static ProtocolMapperModel createClaimMapper(String name,
            String tokenClaimName,
            boolean consentRequired, String consentText,
            boolean accessToken, boolean idToken) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, tokenClaimName);

        if (accessToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        }

        if (idToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        }

        mapper.setConfig(config);
        return mapper;
    }

    private static boolean useFullPath(ProtocolMapperModel mappingModel) {
        return "true".equals(mappingModel.getConfig().get(FULL_PATH));
    }
}
