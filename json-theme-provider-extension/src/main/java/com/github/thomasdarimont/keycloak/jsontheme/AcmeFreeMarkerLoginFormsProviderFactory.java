package com.github.thomasdarimont.keycloak.jsontheme;

import com.google.auto.service.AutoService;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(LoginFormsProviderFactory.class)
public class AcmeFreeMarkerLoginFormsProviderFactory extends FreeMarkerLoginFormsProviderFactory {

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new AcmeFreeMarkerLoginFormsProvider(session);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

}
