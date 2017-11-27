package org.funsec;

/**
 *
 * Google Authenticator forces keys to be in Base32 which limits the keyspace to 32letters only.
 *
 * 16, 26 or 32 character strings are presented by providers to the google auth app.
 *
 * 7777777777777777 => 16  => 10bytes => permutations 32^16 ==> 1208925819614629000000000/2000000000
 * 77777777777777777777777777 => 26 => 16 bytes
 * 77777777777777777777777777777777 => 32 => 20 bytes
 *
 * 10 bytes == 80 bits => 2^80
 *
 */
public class GoogleTOTP
{

    public static final byte[] ENCODE_TABLE = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            '2', '3', '4', '5', '6', '7', //=
    };

}
