package org.cloudfoundry.identity.samples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@SpringBootApplication
@EnableAutoConfiguration
@ComponentScan
@Controller
@EnableOAuth2Sso
public class AuthcodeApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(AuthcodeApplication.class, args);
    }

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping("/oidc")
    public String oidc(Authentication authentication) {
        return "oidc";
    }

    @Bean
    public CheckScope scopeChecker() {
        return new CheckScope();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/oidc").authorizeRequests()
            .antMatchers("/oidc").access("@scopeChecker.hasAnyScope(authentication, 'openid')")
            .and()
            .antMatcher("/**").authorizeRequests()
            .antMatchers("/", "/index", "/error").permitAll()
            .anyRequest().authenticated();
    }

    public static class CheckScope {
        public boolean hasAnyScope(Authentication authentication, String... scope) {
            return OAuth2ExpressionUtils.hasAnyScope(authentication, scope);
        }
    }
}
