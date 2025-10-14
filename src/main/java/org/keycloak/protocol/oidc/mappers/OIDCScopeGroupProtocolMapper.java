package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.StringUtil;

public class OIDCScopeGroupProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    private static final String ATTRIBUTE = "attribute";
    private static final String ID = "kc.group.id";
    private static final String NAME = "kc.group.name";
    private static final String PATH = "kc.group.path";
    private static final String SCOPE = "scope";

    public static final String PROVIDER_ID = "oidc-scope-group-protocol-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty attributeProperty = new ProviderConfigProperty();
        attributeProperty.setName(ATTRIBUTE);
        attributeProperty.setLabel("Group Attribute Name");
        attributeProperty.setHelpText(
                "Group attribute name to store claim.  Use kc.group.id, kc.group.name, and kc.group.path to map to those predefined group properties.");
        attributeProperty.setType(ProviderConfigProperty.STRING_TYPE);

        ProviderConfigProperty scopeProperty = new ProviderConfigProperty();
        scopeProperty.setName(SCOPE);
        scopeProperty.setLabel("Scope name");
        scopeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        scopeProperty.setDefaultValue("group");
        scopeProperty.setHelpText(
                "Name of dynamic scope, which will be used to match the default group. Defaults to 'group'");

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
        String attribute = mappingModel.getConfig().get(ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return null;
        }

        AuthorizationRequestContext authorizationRequestContext = clientSessionCtx.getAuthorizationRequestContext();
        String scopeName = mappingModel.getConfig().get(SCOPE);
        String groupName = authorizationRequestContext.getAuthorizationDetailEntries()
                .stream()
                .filter(d -> d.getClientScope().getName().equals(scopeName))
                .map(d -> d.getDynamicScopeParam())
                .findFirst().orElse(null);
        if (groupName != null) {
            Function<GroupModel, String> mapper;
            if (ID.equalsIgnoreCase(attribute)) {
                mapper = GroupModel::getId;
            } else if (NAME.equalsIgnoreCase(attribute)) {
                mapper = GroupModel::getName;
            } else if (PATH.equalsIgnoreCase(attribute)) {
                mapper = ModelToRepresentation::buildGroupPath;
            } else {
                mapper = m -> m.getFirstAttribute(attribute);
            }

            return userSession.getUser().getGroupsStream()
                    .filter(g -> g.getName().equalsIgnoreCase(groupName))
                    .map(mapper)
                    .findFirst().orElse(null);
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
}
