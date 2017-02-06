package com.defence;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws Exception {

        // Pass the arguments to the initialise
        new Main().initialise(args[0], args[1], args[2]);

    }

    private void initialise(String input1, String input2, String input3) throws Exception {

        // Grab the values from the parameters
        BigInteger p = new BigInteger(input1);
        BigInteger g = new BigInteger(input2);
        BigInteger a = new BigInteger(input3);

        // Specify the IP address of the server
        InetAddress addr = InetAddress.getByName("127.0.0.1");

        // Port of the server to connect to
        Socket socket = new Socket(addr, 8080);

        try {
            System.out.println("socket = " + socket);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);

            // Create the random 4 digig nonce
            String nonce = createNonce();

            // Create the diffe helman shared key
            BigInteger key = generateDHSharedkey(g, a, p, out, in);

            // Create the IV
            String iv = createIv(key, nonce);

            byte[] sessionKey = createSessionKey(iv);

            // Send the nonce
            out.println("##NONCE##" + nonce + "####");
            out.flush();

            String file = requestEncryptedFile(out, in, iv, sessionKey);

            System.out.println(file);

        } catch (SocketException e) {
            System.out.println("Server closed connection");
        } finally {
            System.out.println("closing...");
            socket.close();    //close the connection
        }
    }

    /**
     * @param g
     * @param a
     * @param p
     * @param out
     * @param in
     * @return
     * @throws Exception
     */
    private BigInteger generateDHSharedkey(BigInteger g, BigInteger a, BigInteger p, PrintWriter out, BufferedReader in) throws Exception {

        // Create A to send to the server
        String A = "##DHA##" + (g.pow(a.intValue()).mod(p)).toString() + "####";

        // Send A to the server
        out.println(A);

        // Read in the response
        String str = in.readLine();

        // Remove everything except numbers, extract the value from the response
        BigInteger B = BigInteger.valueOf(Long.valueOf(str.replaceAll("[^\\d]", "")));

        return (B.pow(a.intValue()).mod(p));
    }

    /**
     * Create the 4 digit nonce to pass to the server.
     *
     * @return
     */
    private String createNonce() {

        // Generate random 4 digit number
        int R = (int) (Math.random() * 9000) + 1000;

        return String.valueOf(R);
    }

    /**
     * Create the IV consistint of the diffeHelman and nonce key padded using 12 0's
     *
     * @param dhKey
     * @param R
     * @return String
     * @throws Exception
     */
    private String createIv(BigInteger dhKey, String R) throws Exception {

        // Pad the key with zeros
        String paddedKey = String.format("%012d", dhKey.intValue());

        // Prepend the random number to the beginning of the key
        return R + paddedKey;

    }

    /**
     * Has the IV key using SHA-256 and take the first 16 bytes.
     *
     * @param concatenatedKey
     * @return byte[]
     */
    private byte[] createSessionKey(String concatenatedKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(concatenatedKey.getBytes("UTF-8"));

            // Return first 16 bytes
            return Arrays.copyOf(hashed, 16);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new byte[0];
    }


    /**
     * @param out
     * @param in
     * @return
     * @throws Exception
     */
    private String requestEncryptedFile(PrintWriter out, BufferedReader in, String iv, byte[] sessionKey) throws Exception {
        // Request a file
        out.println("##REQFILE####");

        String response = in.readLine();
        String fileContents = response.substring(11, response.indexOf("####"));

        // Decrypt the data
        byte[] data = decrypt(fileContents, iv, sessionKey);

        // Decrypt the data and parse it, to remove the 'DECRYPTED' beginning
        return parseMessage(new String(data));
    }

    /**
     * @param encrypted The BASE64 decoded message to decrypt
     * @return byte[]   The decrypted bytes
     * @throws Exception
     */
    private byte[] decrypt(String encrypted, String iv, byte[] sessionKey) throws Exception {

        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(sessionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        return cipher.doFinal(decoded);
    }

    /**
     * Remove the 'DECRYPTED:' message from the beginning of the output.
     *
     * @param message
     * @return
     */
    private String parseMessage(String message) {
        // Only replace the first occurrence
        return message.replaceFirst("DECRYPTED:", "");
    }

}