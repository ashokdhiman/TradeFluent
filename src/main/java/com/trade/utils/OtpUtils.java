package com.trade.utils;

import java.util.Random;

public class OtpUtils {
    public static String generateOtp(){
        int otpLength=6;
        Random r=new Random();
        StringBuilder otp=new StringBuilder(otpLength);
        for(int i=0;i<otpLength;i++){
            otp.append(r.nextInt(10));
        }

        return otp.toString();
    }
}
