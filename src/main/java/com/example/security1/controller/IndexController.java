package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @GetMapping("/test/login")
    public @ResponseBody
    String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) { // DI (의존성 주입)
        System.out.println("/test/login ===========================");

        // 1번째 방법
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        // UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        // PrincipalDetails 로 받는 이유는 UserDetails 를 상속받았기 때문에 원래 UserDetails 로 받아야함.
        System.out.println("authentication : " + principalDetails.getUser());
        // 2번쨰 방법
        System.out.println("userDetails : " + userDetails.getUsername());

        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody
    String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) { // DI (의존성 주입)

        System.out.println("/test/oauth/login ===========================");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + oAuth2User.getAttributes());

        System.out.println("oauth2User : " + oauth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    // localhost:8080
    // localhost:8080/
    @GetMapping({"", "/"})
    public String index() {
        // 머스테치 기본폴더 src/main/resources/
        // 뷰리졸버 설정 : templates (prefix), .mustache (suffix) 생략가능 ! why ? maven di
        return "index";
    }

    // OAuth 로그인을 해도 PrincipalDetails
    // 일반 로그인을 해도 PrincipalDetails
    @GetMapping("/user")
    public @ResponseBody
    String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails);
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {

        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {

        return "manager";
    }

    // 스프링 시큐리티가 해당 주소를 낚아챈다. - SecurityConfig 파일 생성 후 작동 안함
    @GetMapping("/loginForm")
    public String loginForm() {

        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {

        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입 잘됨. but, 비밀번호 1234 => 시큐리티로 로그인을 할 수 없다. 이유는 패스워드가 암호화가 안되었기 때문에
        return "redirect:/loginForm";
    }


    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 메서드 실행 전
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터정보";
    }

}
