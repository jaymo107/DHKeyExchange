package com.defence;

import com.sun.deploy.util.StringUtils;

import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import static java.awt.SystemColor.text;

public class Main {

    private Random random;

    public static void main(String[] args) throws IOException {

        new Main().initialise(args);

    }

    private void initialise(String[] args) throws IOException {

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
            createSessionKey(key);

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

    private void createSessionKey(BigInteger dhKey) {

        int padAmount = 12;

        // Generate random 4 digit number
        int R = (int) (Math.random() * 9000) + 1000;

        String paddedKey = String.format("%0" + padAmount + "d", dhKey.intValue());

        System.out.println("Random number (R): " + R);

        // Prepend the random number to the beginning of the key
        String newKey = String.valueOf(R) + paddedKey;
        System.out.println("Concatenated key: " + newKey);

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

            System.out.println("Hash: " + hexString.toString());

        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }


}