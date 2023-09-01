package com.example.securityprac.user.controller;

import com.example.securityprac.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/sign")
    public ResponseEntity sign(@RequestBody UserDto userDto){
        if(userService.sign(userDto)){
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody UserDto userDto){
        //token 생성및 반환
        TokenDto tokenDto = userService.login(userDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
