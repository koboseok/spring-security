package com.example.security1.config.oauth;

import com.example.security1.config.CustomBCryptPasswordEncoder;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.FacebookUserInfo;
import com.example.security1.config.oauth.provider.GoogleUserInfo;
import com.example.security1.config.oauth.provider.NaverUserInfo;
import com.example.security1.config.oauth.provider.OAuth2UserInfo;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

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
        // 회원가입 강제 진행
        OAuth2UserInfo oAuth2UserInfo = null;

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {

            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {

            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {

            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));

        } else {

            System.out.println("우리는 구글, 페이스북, 네이버만 지원합니다.");

        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("의미없다");
        String email  = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if (user == null) {
            System.out.println("로그인이 최초입니다.");
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
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
