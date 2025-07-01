package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.dto.SendMailReqDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MailService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private JwtUtil jwtUtil;

    public ApiRespDto<?> sendMail(SendMailReqDto sendMailReqDto, PrincipalUser principalUser){
        if (!principalUser.getEmail().equals(sendMailReqDto.getEmail())){
            return new ApiRespDto<>("failed","잘못된 접근 입니다.",null);
        }
        Optional<User> optionalUser = userRepository.getUserByEmail(sendMailReqDto.getEmail());

        if (optionalUser.isEmpty()){
            return new ApiRespDto<>("failed","사용자 정보를 확인해주세요",null);
        }
        User user = optionalUser.get();

        boolean hasTempRole = user.getUserRoles().stream()
                .anyMatch(userRole -> userRole.getRoleId()==3);

        if (!hasTempRole){
            return new ApiRespDto<>("failed","인증이 필요한 계정이 아닙니다.",null);
        }

        String token = jwtUtil.generateMailVerifyToken(user.getUserId().toString());

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("이메일 인증 입니다.");
        message.setText("링크를 클릭해 인증을 완료해 주세요. :" +
                "http://localhost:8080/mail/verify?verifyToken=" + token);
        javaMailSender.send(message);

        return new ApiRespDto<>("success","인증 메일이 전송되었습니다. 메일을 확인하세요.",null);
    }
}
