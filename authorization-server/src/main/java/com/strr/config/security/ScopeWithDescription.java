package com.strr.config.security;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ScopeWithDescription {
    private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
    private static final Map<String, String> scopeDescriptions = new HashMap<>();
    static {
        scopeDescriptions.put(
                OidcScopes.OPENID,
                "This application will be able to read your openid information."
        );
        scopeDescriptions.put(
                OidcScopes.PROFILE,
                "This application will be able to read your profile information."
        );
        scopeDescriptions.put(
                "web",
                "This application will be able to visit your web resource"
        );
    }

    public final String scope;
    public final String description;

    private ScopeWithDescription(String scope) {
        this.scope = scope;
        this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
    }

    public static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));

        }
        return scopeWithDescriptions;
    }

    public static void addScope(Set<String> scopes) {
        scopes.addAll(scopeDescriptions.keySet());
    }
}
