package com.trade.controller;

import com.trade.config.JwtProvider;
import com.trade.modal.TwoFactorOTP;
import com.trade.modal.User;
import com.trade.repository.UserRepository;
import com.trade.response.AuthResponse;
import com.trade.service.CustomUserDetailService;
import com.trade.service.EmailService;
import com.trade.service.TwoFactorOTPService;
import com.trade.utils.OtpUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CustomUserDetailService customUserDetailService;

    @Autowired
    TwoFactorOTPService twoFactorOTPService;

    @Autowired
    private EmailService emailService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> register(@RequestBody User user) throws Exception {
        User emailExist=userRepository.findByEmail(user.getEmail());
        if(emailExist!=null) throw new Exception("email already exists");

        User newUser =new User();
        newUser.setEmail(user.getEmail());
        newUser.setPassword(user.getPassword());
        newUser.setFullName(user.getFullName());

        User savedUser=userRepository.save(newUser);

        Authentication auth=new UsernamePasswordAuthenticationToken(user.getEmail(),user.getPassword());
        SecurityContextHolder.getContext().setAuthentication(auth);

        String jwt= JwtProvider.generateToken(auth);

        AuthResponse authResponse=new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setStatus(true);
        authResponse.setMessage("register successful");


        return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> login(@RequestBody User user) throws Exception{
        String username=user.getEmail();
        String password=user.getPassword();
        Authentication auth=authenticate(username,password);
        SecurityContextHolder.getContext().setAuthentication(auth);

        String jwt= JwtProvider.generateToken(auth);

        User authUser=userRepository.findByEmail(username);

        if(user.getTwoFactorAuth().isEnabled()){
            AuthResponse authResponse=new AuthResponse();
            authResponse.setMessage("Two factor auth is enabled");
            authResponse.setTwoFactorAuthEnable(true);
            String otp= OtpUtils.generateOtp();

            TwoFactorOTP oldtwoFactorOtp=twoFactorOTPService.findByUser(authUser.getId());
            if(oldtwoFactorOtp!=null){
                twoFactorOTPService.deleteTwoFactorOtp(oldtwoFactorOtp);
            }

            TwoFactorOTP newTwoFactorOtp=twoFactorOTPService.createTwoFactorOtp(authUser,otp,jwt);

            emailService.sendVerificationOtpEmail(username,otp);

            authResponse.setSession(newTwoFactorOtp.getId());

            return new ResponseEntity<>(authResponse,HttpStatus.ACCEPTED);
        }

        AuthResponse authResponse=new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setStatus(true);
        authResponse.setMessage("login successful");

        return new ResponseEntity<>(authResponse, HttpStatus.ACCEPTED);
    }

    private Authentication authenticate(String username, String password) {
        UserDetails userDetails=customUserDetailService.loadUserByUsername(username);

        if(userDetails==null || !password.equals(userDetails.getPassword()))
            throw new BadCredentialsException("Invalid username or password");

        return new UsernamePasswordAuthenticationToken(userDetails,password,userDetails.getAuthorities());
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifySigninOtp(@PathVariable String otp,@RequestParam String id) throws Exception {
        TwoFactorOTP twoFactorOTP=twoFactorOTPService.findById(id);
        if(twoFactorOTPService.varifyTwofactorOtp(twoFactorOTP,otp)){
            AuthResponse response=new AuthResponse();
            response.setMessage("Two factor authentication verified");
            response.setTwoFactorAuthEnable(true);
            response.setJwt(twoFactorOTP.getJwt());

            return new ResponseEntity<>(response,HttpStatus.OK);
        }
        throw new Exception("Invalid otp");
    }
}
