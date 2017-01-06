package component.encryption.play;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import pamm.infrastructure.component.FileEncryption;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class FileEncryptionTest
{

    private FileEncryption fileEncryption = new FileEncryption();

    //Note that tests will create an encrypted and decrypted folder in the user home directory if it does not exist

    @Rule
    public TemporaryFolder folder= new TemporaryFolder();

    @Test
    public void successfulFileEncryptionAndDecryption() throws IOException
    {
        //Create new temporary file
        File createdFile = folder.newFile("testFile.test.txt");

        Path filePath = createdFile.toPath();

        //Write content to file
        List<String> lines = Arrays.asList("Hello, World");

        Files.write(filePath, lines, Charset.forName("UTF-8"));

        //Assert that line has been written to file correctly
        FileInputStream fileInputStream = new FileInputStream(createdFile);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream));

        String firstLine = bufferedReader.readLine();

        Assert.assertEquals(lines.get(0), firstLine);

        //Encrypt file
        File encryptedFile = fileEncryption.encrypt(createdFile, "helloWorld");

        fileInputStream = new FileInputStream(encryptedFile);
        bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream));

        firstLine = bufferedReader.readLine();

        //Assert encrypted file does not match file
        Assert.assertNotEquals(lines.get(0), firstLine);

        //Close streams
        bufferedReader.close();
        fileInputStream.close();

        //Decrypt file
        File decryptedFile = fileEncryption.decrypt(encryptedFile, "helloWorld");

        fileInputStream = new FileInputStream(decryptedFile);
        bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream));

        firstLine = bufferedReader.readLine();

        //Assert decrypted file is the same as the original file
        Assert.assertEquals(lines.get(0), firstLine);

        //Close off all files
        bufferedReader.close();
        fileInputStream.close();

        //Delete files created by test, leave folder in tact as it may be in use in production
        Files.deleteIfExists(encryptedFile.toPath());
        Files.deleteIfExists(decryptedFile.toPath());
    }

    @Test
    public void failedDecryption() throws IOException
    {
        //Create new temporary file
        File createdFile = folder.newFile("testFile.test.txt");

        Path filePath = createdFile.toPath();

        //Write content to file
        List<String> lines = Arrays.asList("Hello, World");

        Files.write(filePath, lines, Charset.forName("UTF-8"));

        //Encrypt file, process is correct if successful encryption and decryption test passes
        File encryptedFile = fileEncryption.encrypt(createdFile, "helloWorld");

        //Decrypt file with wrong password
        File decryptedFile = fileEncryption.decrypt(encryptedFile, "helloworld");

        //Assert decrypted file is empty due to incorrect password. BadPaddingException thrown is expected.
        Assert.assertNull(decryptedFile);

        //Delete files created by test, leave folder in tact as it may be in use in production. Decrypted file is null due to an error for incorrect password, so it gets deleted by the function
        Files.deleteIfExists(encryptedFile.toPath());
    }

}
