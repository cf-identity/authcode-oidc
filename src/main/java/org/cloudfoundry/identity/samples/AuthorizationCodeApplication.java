package org.cloudfoundry.identity.samples;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import static org.cloudfoundry.identity.samples.utils.Utils.getTokenValue;
import static org.cloudfoundry.identity.samples.utils.Utils.getUsername;
import static org.cloudfoundry.identity.samples.utils.Utils.multiline;
import static org.cloudfoundry.identity.samples.utils.Utils.prettyPrint;
import static org.springframework.http.HttpMethod.GET;

@SpringBootApplication
@EnableAutoConfiguration
@ComponentScan
@Controller
@EnableOAuth2Sso
public class AuthorizationCodeApplication extends WebSecurityConfigurerAdapter {

    @RequestMapping("/")
    public String nonsecure() {
        return "index";
    }

    @RequestMapping("/oidc")
    public String secure(OAuth2Authentication authentication, Model model) throws IOException {
        model.addAttribute("jwt", prettyPrint(authentication));
        model.addAttribute("username", getUsername(authentication));
        model.addAttribute("token", multiline(getTokenValue(authentication), 80));
        return "oidc";
    }

    @RequestMapping("/my-info")
    public String myinfo_pure_spring(OAuth2Authentication authentication, Model model) throws IOException, URISyntaxException {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.set("Authorization", "bearer "+getTokenValue(authentication));
        RequestEntity<String> entity = new RequestEntity<>(headers, GET, new URI("http://localhost:8080/uaa/userinfo"));
        ResponseEntity<Map> userInfo = template.exchange(entity, Map.class);
        model.addAttribute("userinfo", prettyPrint(userInfo.getBody()));
        return "myinfo";
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/oidc").authorizeRequests()
            .antMatchers("/oidc").access("@checkScope.hasAnyScope(authentication, 'openid')")
            .and()
            .antMatcher("/my-info").authorizeRequests()
            .antMatchers("/my-info").access("@checkScope.hasAnyScope(authentication, 'openid')")
            .and()
            .antMatcher("/**").authorizeRequests()
            .antMatchers("/", "/error").permitAll()
            .anyRequest().authenticated()
            .and()
            .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/");
    }

    @Bean
    public CheckScope checkScope() {
        return new CheckScope();
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationCodeApplication.class, args);
    }

    public static class CheckScope {
        public boolean hasAnyScope(Authentication authentication, String... scope) {
            return OAuth2ExpressionUtils.hasAnyScope(authentication, scope);
        }
    }
}
