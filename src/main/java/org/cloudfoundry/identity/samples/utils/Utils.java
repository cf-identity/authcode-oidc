package org.cloudfoundry.identity.samples.utils;


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

    public static String getUsername(OAuth2Authentication authentication) throws IOException {
        return (String) getClaims(getJwt(authentication)).get("user_name");
    }

    public static String prettyPrint(OAuth2Authentication authentication) throws IOException {
        Jwt jwt = getJwt(authentication);
        return prettyPrint(jwt);
    }

    public static String prettyPrint(Jwt jwt) throws IOException {
        Map<String,Object> map = getClaims(jwt);
        return prettyPrint(map);
    }
    public static String prettyPrint(Map map) throws IOException {
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

    public static Jwt getJwt(OAuth2Authentication authentication) {
        String jwtValue = getTokenValue(authentication);
        return JwtHelper.decode(jwtValue);
    }

    public static String getTokenValue(OAuth2Authentication authentication) {
        return ((OAuth2AuthenticationDetails)authentication.getDetails()).getTokenValue();
    }

    public static Map<String, Object> getClaims(Jwt jwt) throws IOException {
        return m.readValue(jwt.getClaims(), new TypeReference<Map<String,Object>>() {});
    }

    public static String multiline(String s, int cols) {
        StringBuffer result = new StringBuffer();
        int count = 0;
        for (char c : s.toCharArray()) {
            if (++count % cols == 0) {
                result.append('\n');
            }
            result.append(c);
        }
        return result.toString();
    }
}
