package pamm.infrastructure.component;

import play.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class FileEncryption {

    private static final Logger.ALogger LOG = Logger.of(FileEncryption.class);

    private static final String homeDirectory = System.getProperty("user.home");

    private static final String keyAlgorithm = "PBKDF2WithHmacSHA1";

    private static final String specification = "AES";

    private static final String cipherInstance = "AES/CBC/PKCS5Padding";

    public File encrypt(File rawFile, String password) {

        String fileName = rawFile.getName();

        byte[] salt = new byte[8];

        SecureRandom secureRandom = new SecureRandom();

        //Generate new 8 byte salt using SecureRandom
        secureRandom.nextBytes(salt);

        try {
            //Setup secret key generation algorithm using the Password-Based Key Derivation Function found in PKCS #5 v2.0.
            SecretKeyFactory factory = SecretKeyFactory.getInstance(keyAlgorithm);
            //NOTE: 128 is secure enough, however to maximise security please install the JCE from the Oracle Java website and change to 256.
            //65536 and 256 is the standard combination for security. 256 requires Java Cryptography Extension (JCE) to be installed however, 128 can be used in default Java
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey secretKey = factory.generateSecret(keySpec);
            //Use AES specification
            SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), specification);

            //Setup Cipher with AES (128 keysize)
            Cipher cipher = Cipher.getInstance(cipherInstance);
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            AlgorithmParameters params = cipher.getParameters();

            //Setup initialisation vector to add randomness to the encryption process
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            //Create directory in user home to store encrypted files
            Path encryptedPath = Paths.get(homeDirectory + "/encrypted");
            Files.createDirectories(encryptedPath);

            FileInputStream fileInputStream = new FileInputStream(rawFile);

            //Create output file to store on disk
            File encryptedFile = new File(encryptedPath.toString() + "/" + fileName + ".aes");
            try (FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile)) {

                //Add the salt and IV to the encrypted file as headers
                fileOutputStream.write(salt);
                fileOutputStream.write(iv);

                byte[] input = new byte[64];
                int bytesRead;

                //While there are still file contents to be encrypted
                while ((bytesRead = fileInputStream.read(input)) != -1) {
                    byte[] output = cipher.update(input, 0, bytesRead);
                    if (output != null) {
                        fileOutputStream.write(output);
                    }
                }

                //Finalise the encryption
                byte[] output = cipher.doFinal();
                if (output != null) {
                    fileOutputStream.write(output);
                }

                fileInputStream.close();
                fileOutputStream.flush();
            } catch (Exception e) {
                LOG.error("Exception has occurred during encryption: " + e);

                //Close input stream. Output stream closed by Java try block
                fileInputStream.close();

                //Delete left over file if encryption failed
                encryptedFile.delete();
                return null;
            }

            return encryptedFile;

        } catch (Exception e) {
            LOG.error("Exception has occurred during encryption: " + e);
            return null;
        }

    }

    public File decrypt(File encryptedFile, String password) {

        String fileName = encryptedFile.getName();

        try {

            FileInputStream fileInputStream = new FileInputStream(encryptedFile);

            //Get salt and iv from encrypted file headers. Note that this means this decrypt function will only work with the corresponding encrypt algorithm in the same class
            byte[] salt = new byte[8];
            fileInputStream.read(salt, 0, 8);

            byte[] iv = new byte[16];
            fileInputStream.read(iv, 0, 16);

            //Setup secret key generation algorithm using the Password-Based Key Derivation Function found in PKCS #5 v2.0.
            SecretKeyFactory factory = SecretKeyFactory.getInstance(keyAlgorithm);
            //Values must match all values used to do the encryption.
            //65536 and 256 is the standard combination for security. 256 requires Java Cryptography Extension (JCE) to be installed however, 128 can be used in default Java
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKey secretKey = factory.generateSecret(keySpec);
            //Use AES specification
            SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), specification);

            //Initialise cipher in decrypt mode use the same secret key and iv as used to encrypt
            Cipher cipher = Cipher.getInstance(cipherInstance);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

            //Create directory to store encrypted files
            Path decryptedPath = Paths.get(homeDirectory + "/decrypted");
            Files.createDirectories(decryptedPath);

            //Remove the .aes extension from the file
            fileName = fileName.substring(0, fileName.length() - 4);

            File decryptedFile = new File(decryptedPath.toString() + "/" + fileName);
            try (FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile)) {
                //While there is still content to be decrypted
                byte[] in = new byte[64];
                int read;
                while ((read = fileInputStream.read(in)) != -1) {
                    byte[] output = cipher.update(in, 0, read);
                    if (output != null) {
                        fileOutputStream.write(output);
                    }
                }

                //Finalise decryption
                byte[] output = cipher.doFinal();
                if (output != null) {
                    fileOutputStream.write(output);
                }

                fileInputStream.close();
                fileOutputStream.flush();

            } catch (Exception e) {
                LOG.error("Exception has occurred during decryption: " + e);

                //Close input stream. Output stream closed by Java try block
                fileInputStream.close();

                //Delete left over file if decryption failed
                decryptedFile.delete();
                return null;
            }

            return decryptedFile;

        } catch (Exception e) {
            LOG.error("Exception has occurred during decryption: " + e);
            return null;
        }

    }

}