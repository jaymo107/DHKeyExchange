package com.defence;

import com.sun.deploy.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import static java.awt.SystemColor.text;

public class Main {

    private Random random;
    private String iv;

    public static void main(String[] args) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        new Main().initialise(args);

    }

    private void initialise(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        // Grab the values from the parameters
        BigInteger p = BigInteger.valueOf(Long.parseLong(args[0]));
        BigInteger g = BigInteger.valueOf(Long.parseLong(args[1]));
        BigInteger a = BigInteger.valueOf(Long.parseLong(args[2]));

        // Specify the IP address of the server
        InetAddress addr = InetAddress.getByName("127.0.0.1");

        // Port of the server to connect to
        Socket socket = new Socket(addr, 8080);

        try {
            System.out.println("socket = " + socket);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);

            BigInteger key = generateDHSharedkey(g, a, p, out, in);
            String sessionKey = createSessionKey(key);

            System.out.println(sessionKey);

            // Send the session key
            out.println("##NONCE##" + sessionKey + "####");

            String file = requestEncryptedFile(out, in, sessionKey);

            System.out.println(file);

        } catch (SocketException e) {
            System.out.println("Server closed connection");
        } finally {
            System.out.println("closing...");
            socket.close();    //close the connection
        }
    }

    private BigInteger generateDHSharedkey(BigInteger g, BigInteger a, BigInteger p, PrintWriter out, BufferedReader in) throws IOException {

        // Create A to send to the server
        String A = "##DHA##" + (g.pow(a.intValue()).mod(p)).toString() + "####";

        // Send A to the server
        out.println(A);

        // Read in the response
        String str = in.readLine();

        BigInteger B = BigInteger.valueOf(Long.valueOf(str.replaceAll("[^\\d]", "")));

        System.out.println("String from server (B): " + B.toString());

        BigInteger key = (B.pow(a.intValue()).mod(p));

        System.out.println("Shared key is: " + key);

        return key;
    }

    private String createSessionKey(BigInteger dhKey) {

        int padAmount = 12;

        // Generate random 4 digit number
        int R = (int) (Math.random() * 9000) + 1000;

        String paddedKey = String.format("%0" + padAmount + "d", dhKey.intValue());

        System.out.println("Random number (R): " + R);

        // Prepend the random number to the beginning of the key
        String newKey = String.valueOf(R) + paddedKey;
        System.out.println("Concatenated key: " + newKey);

        this.iv = newKey;

        MessageDigest digest = null;

        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(newKey.getBytes("UTF-8"));

            // Get first 16 bytes
            byte[] first16Bytes = Arrays.copyOfRange(hashed, 0, 16);

            StringBuilder hexString = new StringBuilder();

            for (byte first16Byte : first16Bytes) {
                String hex = Integer.toHexString(0xff & first16Byte);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            System.out.println("Hash: " + hexString.substring(0, 16));
            return hexString.substring(0, 16);

        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return "";
    }

    private String requestEncryptedFile(PrintWriter out, BufferedReader in, String key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // Request a file
        out.println("##REQFILE####");

        String response = in.readLine();

        System.out.println("File response: " + response);

        String fileContents = response.substring(11, response.indexOf("####"));
        System.out.println("File contents: " + fileContents);

        System.out.println("IV should be 16 characters long, actual is: " + this.iv.length());

        IvParameterSpec iv = new IvParameterSpec(this.iv.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(fileContents));

        //return new String(original);

        //byte[] original = cipher.doFinal(decoded);
        return "";
        //return new String(original);

    }

}