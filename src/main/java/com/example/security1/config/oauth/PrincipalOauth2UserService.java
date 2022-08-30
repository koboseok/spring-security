package com.example.security1.config.oauth;

import com.example.security1.config.CustomBCryptPasswordEncoder;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    // 로그인 후 후처리되는 함수
    // 구굴로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {



        System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); //registrationId 로 어떤 OAuth로 로그인했는지 확인 가능
        System.out.println("getAccessToken : " + userRequest.getAccessToken().getTokenValue());
        /*
        --> super.loadUser(userRequest).getAttributes()
        {
            sub=117149341927980545524,
            name=Boseok Ko,
            given_name=Boseok,
            family_name=Ko,
            picture=https://lh3.googleusercontent.com/a/AItbvmkiLG0fS3JthFViBBgLntYgYlnJzVdoJLwB2S3x=s96-c,
            email=gopseok2@gmail.com,
             email_verified=true,
             locale=ko
         }
            => 회원가입  시키기
            username = "google_117149341927980545524"
            password = "암호화(겟인데어)"
            email = "gopseok2@gmail.com"
            role = "ROLE_USER"
            provider = "google"
            providerId = "117149341927980545524"
        */
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글 로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code를 리턴 (OAuth-client 라이브러리) -> AccessToken 요청
        // -> userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필을 받아준다.
        System.out.println("getAttribute : " + super.loadUser(userRequest).getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("의미없다");
        String email  = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if (user == null) {
            System.out.println("구글 로그인이 최초입니다.");
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        }else {
            System.out.println("구글 로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
