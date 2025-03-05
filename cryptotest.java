import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FileEncryptDecrypt {

    static {
        // Adding BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();

    public static void main(String[] args) throws Exception {
        // S3 input/output configuration
        String inputBucket = "your-input-bucket";
        String inputKey = "your-input-file.txt";
        String outputBucket = "your-output-bucket";
        String outputKey = "your-output-file.txt";
        String publicKeyBucket = "your-public-key-bucket";
        String publicKeyKey = "your-public-key.pem";

        // Load the public key from S3
        RSAPublicKey publicKey = loadPublicKeyFromS3(publicKeyBucket, publicKeyKey);

        // Download the input file from S3
        byte[] fileData = downloadFileFromS3(inputBucket, inputKey);

        // Perform encryption
        byte[] encryptedData = encryptFile(fileData, publicKey);

        // Upload the encrypted file to S3
        uploadFileToS3(outputBucket, outputKey, encryptedData);

        System.out.println("File encrypted and uploaded to S3 successfully.");
    }

    private static byte[] encryptFile(byte[] fileData, RSAPublicKey publicKey) throws Exception {
        // Generate AES-256 key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey aesKey = keyGenerator.generateKey();

        // Generate random nonce (12 bytes for AES-GCM)
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        // Perform AES encryption with GCM mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce); // 128-bit tag length
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        byte[] encryptedFile = cipher.doFinal(fileData);

        // Encrypt AES key using RSA (public key encryption)
        byte[] encryptedAesKey = encryptAesKeyWithRsa(aesKey, publicKey);

        // Combine encrypted AES key, nonce, and the ciphertext
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedAesKey);
        outputStream.write(nonce);
        outputStream.write(encryptedFile);

        return outputStream.toByteArray();
    }

    private static byte[] encryptAesKeyWithRsa(SecretKey aesKey, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    private static void uploadFileToS3(String bucketName, String objectKey, byte[] fileData) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(fileData);
        PutObjectRequest putRequest = new PutObjectRequest(bucketName, objectKey, byteArrayInputStream, null);
        s3Client.putObject(putRequest);
    }

    private static byte[] downloadFileFromS3(String bucketName, String objectKey) throws IOException {
        InputStream inputStream = s3Client.getObject(new GetObjectRequest(bucketName, objectKey)).getObjectContent();
        return inputStream.readAllBytes();
    }

    private static RSAPublicKey loadPublicKeyFromS3(String bucketName, String objectKey) throws Exception {
        byte[] keyBytes = downloadFileFromS3(bucketName, objectKey);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    // Decryption Process (optional, for testing purposes)
    public static byte[] decryptFile(byte[] encryptedData, RSAPrivateKey privateKey) throws Exception {
        // Extract the encrypted AES key, nonce, and ciphertext
        byte[] encryptedAesKey = new byte[privateKey.getModulus().bitLength() / 8];
        System.arraycopy(encryptedData, 0, encryptedAesKey, 0, encryptedAesKey.length);

        byte[] nonce = new byte[12];
        System.arraycopy(encryptedData, encryptedAesKey.length, nonce, 0, nonce.length);

        byte[] ciphertext = new byte[encryptedData.length - encryptedAesKey.length - nonce.length];
        System.arraycopy(encryptedData, encryptedAesKey.length + nonce.length, ciphertext, 0, ciphertext.length);

        // Decrypt AES key using RSA (private key decryption)
        SecretKey aesKey = decryptAesKeyWithRsa(encryptedAesKey, privateKey);

        // Perform AES decryption with GCM mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        return cipher.doFinal(ciphertext);
    }

    private static SecretKey decryptAesKeyWithRsa(byte[] encryptedAesKey, RSAPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(encryptedAesKey);
        return new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
    }

    // You can add methods to load the private key similarly if you need the decryption to work.
}
