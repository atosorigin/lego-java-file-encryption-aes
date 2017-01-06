# Java AES File Encryption
Lego Brick for Java based AES file encryption taking in a raw file and password.

To use, simply inject the FileEncryption class into your class and run 
  .encrypt(file, password) to encrypt, or
  .decrypt(file, password) to decrypt.
  
Remember to change the package in the code to where you are keeping the files.
  
By default, encrypted and decrypted files are saved to 
  {user_directory}/encrypted
  {user_directory}/decrypted
Change this in the code or manually move the files after.

                Path encryptedPath = Paths.get(homeDirectory + "/encrypted");
                Files.createDirectories(encryptedPath);
                
                Path decryptedPath = Paths.get(homeDirectory + "/decrypted");
                Files.createDirectories(decryptedPath);

The salt and intialisation vectors are saved into the encrypted file as both values can be public, only the password should be private. If you prefer to save these elsewhere, modify the two code blocks:

In encrypt:

                fileOutputStream.write(salt);
                fileOutputStream.write(iv);

In decrypt:

                fileInputStream.read(salt, 0, 8);
                fileInputStream.read(iv, 0, 16);

Note: Will work with out of the box Java 7+, however for better security, please install Java Crytography Extensions (JCE) from the Oracle Java site and then change the Cipher to use 256-bits instead of 128 which is the most Java without extensions can handle.
