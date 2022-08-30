package com.example.security1.config;

import com.example.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션
@RequiredArgsConstructor

// 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
// preAuthorize, postAuthorize 어노테이션 활성화 , secured 어노테이션 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)

public class SecurityConfig extends WebSecurityConfigurerAdapter{

    private final PrincipalOauth2UserService principalOauth2UserService;

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    /*@Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만되면 들아갈 수 있는 주소 !
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")// /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다. => 컨트롤러에서 /login 을 만들지 않아도된다.
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요하다. Tip -> 코드로 받는게 아니라 엑세스토큰 + 사용자프로필 정보를 받는다. --> oauth 라이브러리
                .userInfoEndpoint()
                .userService(principalOauth2UserService);


    }


    // 1. 코드받기 (인증) , 2. 엑세스토큰(권한)
    // 3. 사용자 프로필 정보를 가져오고 , 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
    // 4-2. (이메일, 전화번호, 이름, 아이디) 쇼필몰 -> (집주소), 백화점몰 -> (vip 등급, 일반등급)
}
