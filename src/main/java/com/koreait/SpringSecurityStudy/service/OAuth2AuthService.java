package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.OAuth2MergeReqDto;
import com.koreait.SpringSecurityStudy.dto.OAuth2SignupReqDto;
import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.entity.UserRole;
import com.koreait.SpringSecurityStudy.repository.Oauth2UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class OAuth2AuthService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserRoleRepository userRoleRepository;
    @Autowired
    private Oauth2UserRepository oauth2UserRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApiRespDto<?> signup(OAuth2SignupReqDto oAuth2SignupReqDto){
        Optional<User> optionalUser = userRepository.getUserByEmail(oAuth2SignupReqDto.getEmail());
        if (optionalUser.isPresent()){
            return new ApiRespDto<>("failed","이미 존재하는 이메일 입니다.",null);
        }

        Optional<User> user = userRepository.addUser(oAuth2SignupReqDto.toEntity(bCryptPasswordEncoder));
        UserRole userRole = UserRole.builder()
                .userId(user.get().getUserId())
                .roleId(3)
                .build();
        userRoleRepository.addUserRole(userRole);
        oauth2UserRepository.insertOAuth2User(oAuth2SignupReqDto.toOAuth2User(user.get().getUserId()));
        return new ApiRespDto<>("success","OAuth2 회원가입 완료",null);
    }

    public ApiRespDto<?> merge(OAuth2MergeReqDto oAuth2MergeReqDto){
        Optional<User> optionalUser = userRepository.getUserByUsername(oAuth2MergeReqDto.getUsername());
        if (optionalUser.isEmpty()){
            return new ApiRespDto<>("failed","사용자 정보를 확인하세요.",null);
        }
        if (!bCryptPasswordEncoder.matches(oAuth2MergeReqDto.getPassword(),optionalUser.get().getPassword())){
            return new ApiRespDto<>("failed","사용자 정보를 확인하세요.",null);
        }
         oauth2UserRepository.insertOAuth2User(oAuth2MergeReqDto.toOAuth2User(optionalUser.get().getUserId()));

        return new ApiRespDto<>("success","회원 가입이 완료되었습니다.",null);
    }
}
