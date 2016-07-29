package org.cloudfoundry.identity.samples;


import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.GsonBuilder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

public class Utils {


    static ObjectMapper m =  new ObjectMapper();

    static String getUsername(OAuth2Authentication authentication) throws IOException {
        return (String) getClaims(getJwt(authentication)).get("user_name");
    }

    static String prettyPrint(OAuth2Authentication authentication) throws IOException {
        Jwt jwt = getJwt(authentication);
        return prettyPrint(jwt);
    }

    static String prettyPrint(Jwt jwt) throws IOException {
        Map<String,Object> map = getClaims(jwt);
        String result = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create()
            .toJson(map);
        return result
            .substring(1, result.length()-1)
            .replace("\"", "&quot;")
            .replace("\n","<br/>")
            .replace(" ", "&nbsp;");
    }

    static Jwt getJwt(OAuth2Authentication authentication) {
        String jwtValue = ((OAuth2AuthenticationDetails)authentication.getDetails()).getTokenValue();
        return JwtHelper.decode(jwtValue);
    }

    static Map<String, Object> getClaims(Jwt jwt) throws IOException {
        return m.readValue(jwt.getClaims(), new TypeReference<Map<String,Object>>() {});
    }
}
