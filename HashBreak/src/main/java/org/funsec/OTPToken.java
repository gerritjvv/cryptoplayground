package org.funsec;

import org.apache.commons.codec.binary.Base32;
import org.funsec.hmac.HOTP;
import org.funsec.util.Utils;

import java.time.Instant;

import static org.funsec.util.Utils.asCharStr;

/*
 * OTP token to help with attack studies.
 * Contains the original key used and the time step when the otp token was generated.
 */
public class OTPToken {

    private final long time; //floor(Instant.seconds/30)
    private final byte[] key;

    private final int otp;

    public OTPToken(long time, byte[] key, int otp) {
        this.time = time;
        this.key = key;
        this.otp = otp;
    }

    public long getTime() {
        return time;
    }

    public byte[] getKey() {
        return key;
    }

    public int getOtp() {
        return otp;
    }

    public static OTPToken[] stealOTP(int keyLen, byte[] encodeTable, int tokensToSteal, String shaAlgo) {
        return stealOTP(keyLen, encodeTable, tokensToSteal, shaAlgo, false);
    }

    /**
     * Return tokensToSteal OTPToken(s) with the same key, randomly generated once from the encodeTable.
     * token[0] = timeInstant+0, token[1] = timeInstant+1 ...
     * <p>
     * Simulates distinct stolen tokens in time e.g tokensToSteal = 3 are tokens stolen for 1.5 minutes.
     */
    public static OTPToken[] stealOTP(int keyLen, byte[] encodeTable, int tokensToSteal, String shaAlgo, boolean base32decode) {

        byte[] k = Utils.genRandomKey(keyLen, encodeTable);

        if(base32decode) {
            k = new Base32().decode(k);
        }

        try {
            final long timeInstant = Math.floorDiv(Instant.now().getEpochSecond(), (long) 30);

            OTPToken[] tokens = new OTPToken[tokensToSteal];
            for (int i = 0; i < tokensToSteal; i++) {

                //we do timeInstant + i to get the next 30 second hop.
                //here we simulate stealing n otp tokens in time.
                tokens[i] = new OTPToken(timeInstant + i, k, HOTP.otp(k, timeInstant + i, 6, shaAlgo, -1));
            }

            return tokens;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * True if the key can generate matching otp equal to that of the tokens given.
     */
    public static final boolean matchWithStolen(OTPToken[] tokens, byte[] key, String shaAlgo) {

        for (OTPToken token : tokens) {
            try {

                int otp = HOTP.otp(key, token.getTime(), 6, shaAlgo, -1);

                if(otp != token.getOtp())
                    return false;

            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }

        return true;
    }

    public static final void printOtpValues(OTPToken[] tokens, byte[] key, String shaAlgo) {
        StringBuilder buff = new StringBuilder();

        buff.append("key : " + asCharStr(key));

        for (OTPToken token : tokens) {
            try {

                int otp = HOTP.otp(key, token.getTime(), 6, shaAlgo, -1);

                buff.append("\t").append(otp);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }


        System.out.println(buff.toString());
    }
}
