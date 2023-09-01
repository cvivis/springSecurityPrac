package com.example.securityprac.user.service;

import com.example.securityprac.user.controller.TokenDto;
import com.example.securityprac.user.controller.UserDto;
import com.example.securityprac.user.domain.User;
import com.example.securityprac.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;


    public Boolean findEmail(String email){
        if(userRepository.findByEmail(email) == null){
            return false;
        }
        return true;
    }
    public Boolean sign(UserDto userDto){
        try{
            User user = User.builder()
                    .email(userDto.getEmail())
                    .password(encoder.encode(userDto.getPassword()))
                    .build();
            userRepository.save(user);
            return true;
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

//    public TokenDto login(UserDto userDto){
//        //비밀번호 암호화 한것과 비교
//        User selectedUser = userRepository.findByEmail(userDto.getEmail());
//        if(encoder.matches(userDto.getPassword(), selectedUser.getPassword())){
//            // 토큰 발급
//        }
//
//    }
}
