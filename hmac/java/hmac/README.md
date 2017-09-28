# HMAC One Time Password implementation and tests


## Usage

```java

HOTP hotp1 = HOTP.newTOTPInstance(HOTP.SHA_1);

HOTP hotp32 = HOTP.newTOTPInstance(HOTP.SHA_256);

HOTP hotp64 = HOTP.newTOTPInstance(HOTP.SHA_512);


byte[] secret1 = getSecret();

byte[] secret32 = getSecret32();

byte[] secret64 = getSecret64();

int otp1 = htp1.calcOtp(secret)

int otp2 = htp32.calcOtp(secret32)

int otp3 = htp64.calcOtp(secret64)


```

## Verification

See ```test/java/org.funsec.hmac```

## Demo

Use ```./runserver.sh``` and ```./runclient.sh``` to verify and generate tokens based on TOTP.