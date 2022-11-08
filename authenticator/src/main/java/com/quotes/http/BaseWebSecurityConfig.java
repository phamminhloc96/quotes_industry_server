package com.quotes.http;

//import de.codetano.ntc.common.jwt.BaseJwtAuthenticationFilter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class BaseWebSecurityConfig {
//        extends WebSecurityConfigurerAdapter {
//    private final BaseJwtAuthenticationFilter jwtAuthenticationFilter;
//
//    public BaseWebSecurityConfig(BaseJwtAuthenticationFilter jwtAuthenticationFilter) {
//        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
//    }
//
//    @Override
//    final protected void configure(HttpSecurity http) throws Exception {
//        http
//            .csrf().disable()
//            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//            .exceptionHandling().authenticationEntryPoint(new NoAuthenticationEntryPoint())
//            .and()
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//            .and()
//            .authorizeRequests()
//            // Swagger
//            // TODO: remove ?
//            .antMatchers(
//                "/v2/api-docs",
//                "/swagger-ui.html/**",
//                "/webjars/**",
//                "/swagger-resources/**")
//            .permitAll()
//        ;
//
//        customConfiguration(http);
//    }
//
//    protected void customConfiguration(HttpSecurity http) throws Exception {
//        // no user forced, because gateway service should handle token check
//        // each service must not be available from the internet except gateway
//
////       http
////           .authorizeRequests()
////           .anyRequest()
////           .authenticated()
////           ;
//    }
//
//    @Bean
//    public BCryptPasswordEncoder encoder() {
//        return new BCryptPasswordEncoder();
//    }
}
