package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.IDToken;

public class OIDCScopeGroupProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static final String PROVIDER_ID = "oidc-scope-group-protocol-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty fullPathProperty = new ProviderConfigProperty();
        fullPathProperty.setName("full.path");
        fullPathProperty.setLabel("Full group path");
        fullPathProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullPathProperty.setDefaultValue("true");
        fullPathProperty.setHelpText(
                "Include full path to group i.e. /top/level1/level2, false will just specify the group name");

        configProperties.add(fullPathProperty);

        ProviderConfigProperty scopeProperty = new ProviderConfigProperty();
        scopeProperty.setName("scope");
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
        AuthorizationRequestContext authorizationRequestContext = clientSessionCtx.getAuthorizationRequestContext();

        String scopeName = mappingModel.getConfig().get("scope");
        Optional<String> groupName = authorizationRequestContext.getAuthorizationDetailEntries()
                .stream()
                .filter(d -> d.getClientScope().getName().equals(scopeName))
                .map(d -> d.getDynamicScopeParam())
                .findFirst();

        if (groupName.isPresent()) {
            Optional<String> membership = userSession.getUser().getGroupsStream()
                    .filter(g -> g.getName().equals(groupName.get()))
                    .map(useFullPath(mappingModel)
                            ? ModelToRepresentation::buildGroupPath
                            : GroupModel::getName)
                    .findFirst();
            if (membership.isPresent()) {
                OIDCAttributeMapperHelper.mapClaim(idToken, mappingModel, membership.get());
            }
        }
    }

    public static ProtocolMapperModel create(String name,
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
        return "true".equals(mappingModel.getConfig().get("full.path"));
    }
}
