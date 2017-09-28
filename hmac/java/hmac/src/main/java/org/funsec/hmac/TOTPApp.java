package org.funsec.hmac;

import sun.security.jca.Providers;

import javax.crypto.Mac;
import java.io.*;
import java.security.*;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import java.util.function.Function;

public class TOTPApp {

    private static Console console = System.console();

    public static void main(String[] args) throws Throwable {

        Map<String, Object> opts = argumentsAsMap(args);

        try {
            if (opts.get("server") != null) {
                runServer(readSecret());
                System.exit(0);
            } else if (opts.get("client") != null) {
                runClient(readSecret());
                System.exit(0);
            } else if (opts.get("plotdata") != null) {
                runPlotData();
                System.exit(0);
            } else {
                printHelp();
                System.exit(-1);
            }
        } catch (RuntimeException rte) {
            System.out.println(rte.getMessage());
            System.exit(-1);
        }
    }

    private static void runPlotData() throws NoSuchAlgorithmException, InvalidKeyException, InterruptedException, IOException {

        final int iterations = 10000;

        writeOutput("/tmp/hotp_securerandom_i1000_" + System.currentTimeMillis() + ".csv",
                (writer) -> {

                    SecureRandom random = new SecureRandom();

                    for (int i = 0; i < iterations; i++) {
                        try {
                            writer.write(String.valueOf(random.nextInt()));
                            writer.write('\n');

                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });

        final long baseTime = System.currentTimeMillis();

        Function<String, Consumer<Writer>> otpFn = (algo) ->
                (Writer writer) -> {

                    byte[] secret = "1234567890".getBytes();


                    long currentTime = baseTime;
                    long seconds30InMills = 30L * 1000L;

                    for (int i = 0; i < iterations; i++) {
                        try {
                            int totp = HOTP.otp(secret,
                                    Math.floorDiv(Math.floorDiv(currentTime, 1000), 30),
                                    6,
                                    HOTP.SHA_1,
                                    -1);

                            currentTime += seconds30InMills;

                            writer.write(String.valueOf(totp));
                            writer.write('\n');

                        } catch (Throwable e) {
                            throw new RuntimeException(e);
                        }
                    }
                };


        writeOutput("/tmp/hotp_totpsha1_i10000_" + System.currentTimeMillis() + ".csv", otpFn.apply(HOTP.SHA_1));
        writeOutput("/tmp/hotp_totpsha256_i10000_" + System.currentTimeMillis() + ".csv", otpFn.apply(HOTP.SHA_256));
        writeOutput("/tmp/hotp_totpsha512_i10000_" + System.currentTimeMillis() + ".csv", otpFn.apply(HOTP.SHA_512));


    }

    private static void writeOutput(String filePath, Consumer<Writer> cl) throws IOException {
        File file = new File(filePath);
        file.createNewFile();

        try (FileWriter writer = new FileWriter(file)) {
            cl.accept(writer);
        }

    }

    private static HOTP readAlgo() {
        System.out.println("Type in 0 = SHA1 [Default], 1 = SHA256, 2 = SHA512: ");

        String line = console.readLine();

        int n = line == null || line.trim().length() == 0 ? 0 : Integer.parseInt(line.trim());

        if (!(0 <= n && n <= 2)) {
            throw new RuntimeException("A valid options of 0,1,2 must be selected");
        }


        final String algo;

        switch (n) {
            case 0:
                algo = HOTP.SHA_1;
                System.out.println("Using SHA1");
                break;
            case 1:
                algo = HOTP.SHA_256;
                System.out.println("Using SHA256");
                break;
            case 2:
                algo = HOTP.SHA_512;
                System.out.println("Using SHA512");
                break;
            default:
                System.out.println("Invalid option chosen using defaul SHA1");
                algo = HOTP.SHA_1;
        }


        return HOTP.newTOTPInstance(algo);
    }

    private static byte[] readSecret() {
        System.out.println("Type in a shared secret key (min 5 chars): ");

        String secret = console.readLine();

        if (secret == null || secret.length() < 5) {
            throw new RuntimeException("A valid secret was not entered and must at least be 5 characters long");
        }


        return secret.getBytes();
    }


    private static int readToken() {
        System.out.println("Type in TOTP token: ");
        System.out.flush();

        String token = console.readLine();

        if (token == null || token.length() != 6) {
            throw new RuntimeException("A valid token was not entered and must be 6 characters long");
        }

        while (token.startsWith("0")) {
            token = token.substring(1, token.length());
        }

        return Integer.parseInt(token);
    }

    private static void runClient(byte[] secret) throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException {

        HOTP hotp = readAlgo();

        while (!Thread.interrupted()) {

            //this calc ensures we start at the 30 second boundaries
            int drift = (int) Math.floorMod(Instant.now().getEpochSecond(), 30L);
            int cnt = (30 - drift);

            for (int i = 0; i < cnt; i++) {

                int token = hotp.calcOtp(secret);

                System.out.print("\r");
                System.out.print("                                                   ");
                System.out.print('\r');
                System.out.print(String.format("%06d", token));
                System.out.print("  [ " + (cnt - (i + 1)) + " ]");
                System.out.flush();

                Thread.sleep(1000);
            }

            System.out.println();

        }
    }

    private static void runServer(byte[] secret) throws InvalidKeyException, NoSuchAlgorithmException {

        HOTP hotp = readAlgo();

        while (!Thread.interrupted()) {
            int token = readToken();
            int serverToken = hotp.calcOtp(secret);

            if (token != serverToken) {
                throw new RuntimeException(serverToken + " does not match entered token " + token);
            }

            System.out.println("Matched: " + serverToken + " == " + token);
        }
    }

    private static void printHelp() {
        System.out.println("Run OTP example server and client where the server waits for typed input generated by the client");
        System.out.println("and then validates the TOTP value against its own calculated TOTP value");
        System.out.println("Example app uses SHA1 T0=0 and X=30seconds");
        System.out.println("Type: -server|-client");
        System.out.println("server => wait for user input from the client");
        System.out.println("client => show output, changing every 30 seconds");
    }

    public static Map<String, Object> argumentsAsMap(String[] args) {
        Map<String, Object> m = new HashMap<>();

        for (int i = 0; i < args.length; i++) {
            String lbl = args[i].trim();

            if (lbl.startsWith("-") && i + 1 < args.length && !args[i + 1].trim().startsWith("-")) {
                m.put(removePrefixes(lbl), args[i + 1].trim());
                i++;
            } else {
                m.put(removePrefixes(lbl), true);
            }
        }

        return m;
    }

    private static String removePrefixes(String lbl) {
        return lbl.replaceFirst("-*", "");
    }
}
