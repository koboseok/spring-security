package com.example.security1.config.auth;

import com.example.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/*
 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다. (Security ContextHolder 에 저장)
 시큐리티가 가지고 있는 세션에 들어갈 수 있는 오브젝트가 정해져있다.
 -> Authentication 타입 객체
    -> 안에는 user 정보가 있어야된다.
        User 오브젝트의 타입 => UserDetails 타입 객체

--> Security Session 안에 들어갈 수 있는 객체는 Authentication 안에  UserDetails(PrincipalDetails) 객체


스프링 시큐리티는 자신만의 세션을 가지고 있다. (시큐리티 세션) -> 필요할때마다 DI를 해서 사용할 수 있다.
-> 여기에 들어갈 수 있는 타입은 Authentication 객체 밖에 없다.
-> Authentication 객체 안에 들어갈 수 있는 타입은 userDetails, oauth2User 이다.
-> 일반로그인 -> userDetails , 구글,페이스북 등 로그인 -> OAuth

==> 하나의 클래스에 userDetails, OAuth 를 상속받아서 로그인 체크

*/
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; // 콤포지션
    private Map<String,Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }
    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳 !
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { // 만료
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 잠김
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 비밀번호 변경 기간
        return true;
    }

    @Override
    public boolean isEnabled() { // 활성화
        // ex
        // 사이트에서 1년동안 회원이 로그인을 안하면 휴면 계정으로 하기로 했다면
        // user.getLoginDate() 를 현재시간을 비교 해서 1년 초과하면 return false
        return true;
    }

    // OAuth 로그인
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
