package com.trade.service;

import com.trade.modal.TwoFactorOTP;
import com.trade.modal.User;

public interface TwoFactorOTPService {
    TwoFactorOTP createTwoFactorOtp(User user,String otp,String jwt);

    TwoFactorOTP findByUser(Long userId);

    TwoFactorOTP findById(String id);

    boolean varifyTwofactorOtp(TwoFactorOTP twoFactorOTP,String otp);

    void deleteTwoFactorOtp(TwoFactorOTP twoFactorOTP);
}
