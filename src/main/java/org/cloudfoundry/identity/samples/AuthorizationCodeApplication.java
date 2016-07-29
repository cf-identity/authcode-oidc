package org.cloudfoundry.identity.samples;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import static org.cloudfoundry.identity.samples.utils.Utils.getUsername;
import static org.cloudfoundry.identity.samples.utils.Utils.prettyPrint;

@SpringBootApplication
@EnableAutoConfiguration
@ComponentScan
@Controller
@EnableOAuth2Sso
public class AuthorizationCodeApplication extends WebSecurityConfigurerAdapter {

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping("/oidc")
    public String oidc(OAuth2Authentication authentication, Model model) throws IOException {
        model.addAttribute("jwt", prettyPrint(authentication));
        model.addAttribute("username", getUsername(authentication));
        return "oidc";
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/oidc").authorizeRequests()
            .antMatchers("/oidc").access("@checkScope.hasAnyScope(authentication, 'openid')")
            .and()
            .antMatcher("/**").authorizeRequests()
            .antMatchers("/", "/index", "/error").permitAll()
            .anyRequest().authenticated()
            .and()
            .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/");
    }

    @Bean
    public CheckScope checkScope() {
        return new CheckScope();
    }
    public static class CheckScope {
        public boolean hasAnyScope(Authentication authentication, String... scope) {
            return OAuth2ExpressionUtils.hasAnyScope(authentication, scope);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationCodeApplication.class, args);
    }


}
