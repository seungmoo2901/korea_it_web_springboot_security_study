package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.dto.SendMailReqDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.entity.UserRole;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRoleRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class MailService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private JwtUtil jwtUtil;

    public ApiRespDto<?> sendMail(SendMailReqDto sendMailReqDto, PrincipalUser principalUser) {
        if (!principalUser.getEmail().equals(sendMailReqDto.getEmail())) {
            return new ApiRespDto<>("failed", "잘못된 접근입니다.", null);
        }

        Optional<User> optionalUser = userRepository.getUserByEmail(sendMailReqDto.getEmail());

        if (optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        User user = optionalUser.get();

        boolean hasTempRole = user.getUserRoles().stream()
                .anyMatch(userRole -> userRole.getRoleId() == 3);

        if (!hasTempRole) {
            return new ApiRespDto<>("failed", "인증이 필요한 계정이 아닙니다.", null);
        }

        String token = jwtUtil.generateMailVerifyToken(user.getUserId().toString());

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("이메일 인증 입니다.");
        message.setText("링크를 클랙해 인증을 완료해주세요. : " +
                "http://localhost:8080/mail/verify?verifyToken=" + token);
        javaMailSender.send(message);

        return new ApiRespDto<>("success", "인증 메일이 전송되었습니다. 메일을 확인하세요.", null);
    }

    public Map<String, Object> verify(String token) {
        Claims claims = null;
        Map<String, Object> resultMap = null;

        try {
            claims = jwtUtil.getClaims(token);
            String subject = claims.getSubject();
            if (!"VerifyToken".equals(subject)) {
                resultMap = Map.of("status", "failed", "message", "잘못된 접근입니다.");
            }
            Integer userId = Integer.parseInt(claims.getId());
            Optional<User> optionalUser = userRepository.getUserByUserId(userId);
            if (optionalUser.isEmpty()) {
                resultMap = Map.of("status", "failed", "message", "존재하지 않는 사용자입니다.");
            }

            Optional<UserRole> optionalUserRole = userRoleRepository.getUserRoleByUserIdAndRoleId(userId, 3);
            if (optionalUserRole.isEmpty()) {
                resultMap = Map.of("status", "failed", "message", "이미 인증이 완료된 메일입니다.");
            } else {
                userRoleRepository.updateRoleId(userId, optionalUserRole.get().getUserRoleId());
                resultMap = Map.of("status", "success", "message", "이메일 인증이 완료되었습니다.");
            }
        } catch (ExpiredJwtException e) {
            resultMap = Map.of("status", "failed", "message", "만료된 인증 요청입니다.\n인증 메일을 다시 요청해주세요.");
        } catch (JwtException e) {
            resultMap = Map.of("status", "failed", "message", "잘못된 접근입니다.\n인증 메일을 다시 요청해주세요.");
        }
        return resultMap;
    }

}
