package com.koreait.SpringSecurityStudy.security.handler;

import com.koreait.SpringSecurityStudy.entity.OAuth2User;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.Oauth2UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private Oauth2UserRepository oauth2UserRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //OAuth2User 정보 가져오기
        DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
        String provider = defaultOAuth2User.getAttribute("provider");
        String providerUserId = defaultOAuth2User.getAttribute("id");
        String email = defaultOAuth2User.getAttribute("email");

        //provider, providerUserId 이미 연동된 사용자 정보가 있는지 DB 조회
        OAuth2User oAuth2User = oauth2UserRepository.getOAuth2UserByProviderAndProviderUserId(provider, providerUserId);

        if (oAuth2User == null){
            response.sendRedirect("http://localhost:3000/auth/oauth/oauth2?provider=" + provider + "&providerUserId=" + providerUserId + "&email=" + email);
            return;
        }
        //연동된 사용자가 있다면? => userId를 통해 회원 정보 조회
        Optional<User> optionalUser = userRepository.getUserByUserId(oAuth2User.getUserId());

        String accessToken = null;
        if(optionalUser.isPresent()){
            accessToken = jwtUtil.generateAccessToken(Integer.toString(optionalUser.get().getUserId()));
        }
        // 최종적으로 accessToken을 쿼리 파라미터로 프론트에 전달
        response.sendRedirect("http://localhost:3000/auth/oauth/oauth2?provider=" + accessToken);
    }

}
