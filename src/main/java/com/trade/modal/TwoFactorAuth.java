package com.trade.modal;

import com.trade.domain.VerificationType;
import lombok.Data;

@Data
public class TwoFactorAuth {
    private boolean isEnabled=false;
    private VerificationType sendTo;

}
