import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Encrypt {
    public static void main(String[] args) {

        if (args.length < 1) {
            System.out.println("Usage:java Encrypt password");
            return;
        }

        // Initialize parameters
        char[] password = args[0].toCharArray();
        String SymmetricKeyEncryption = "AES";
        String KeyStoreImplementation = "JKS";
        String SecureRandomAlgorithm = "SHA1PRNG";
        String DataCipherTransformation = "AES/CBC/PKCS5Padding";
        String ConfigCipherTransformation = "RSA/ECB/PKCS1Padding";
        String SignatureAlgorithm = "SHA256withRSA";
        String KeyStoreFilePath = "keystoreA.jks";
        String KeyStoreAlias = "keyA";
        String KeyStoreTargetAlias = "keyB";
        String InputFilePath = "plaintext.txt";
        String OutputFilePath = "encrypted.txt";
        String OutputCfgFilePath = "encrypted.cfg.txt";

        try {
            // Generate Symmetric Key
            KeyGenerator keyGen = KeyGenerator.getInstance(SymmetricKeyEncryption);
            SecretKey encKey = keyGen.generateKey();

            // Generate Random IV
            byte[] iv = new byte[16];
            SecureRandom secRand = SecureRandom.getInstance(SecureRandomAlgorithm);
            secRand.nextBytes(iv);

            // Initialize Cipher for input file
            Cipher cipher = Cipher.getInstance(DataCipherTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

            // Initialize File and Cipher Streams for input file
            FileInputStream fis = new FileInputStream(InputFilePath);
            FileOutputStream fos = new FileOutputStream(OutputFilePath);
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            StringBuilder inputData = new StringBuilder();

            // Encrypt file using CipherOutputStream
            byte[] b = new byte[8];
            int i;

            while ((i = fis.read(b)) != -1) {
                cos.write(b, 0, i);
            }

            // Close Output Streams
            cos.close();
            fos.close();

            // Read encrypted data to sign later
            fis = new FileInputStream(OutputFilePath);

            while ((i = fis.read(b)) != -1) {
                inputData.append(new String(b, 0, i));
            }

            byte[] encryptedData = inputData.toString().getBytes();

            // Close Input Streams
            fis.close();

            // Load KeyStore using password from argument
            FileInputStream fin = new FileInputStream(KeyStoreFilePath);
            KeyStore keyStore = KeyStore.getInstance(KeyStoreImplementation);
            keyStore.load(fin, password);

            // Retrieve private key from KeyStore
            PrivateKey prvKey = (PrivateKey) keyStore.getKey(KeyStoreAlias, password);

            // Generate Signature and sign encrypted data
            Signature sig = Signature.getInstance(SignatureAlgorithm);
            sig.initSign(prvKey);
            sig.update(encryptedData);
            byte[] sigArray = sig.sign();

            // Retrieve Target Public Key using KeyStore
            PublicKey pubKeyTarget = keyStore.getCertificate(KeyStoreTargetAlias).getPublicKey();
            AlgorithmParameters algParams = cipher.getParameters();

            // Reinitialize Cipher for config file
            cipher = Cipher.getInstance(ConfigCipherTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, pubKeyTarget);
            byte[] keyEncrypted = cipher.doFinal(encKey.getEncoded());

            // Initialize Writer for config file
            PrintWriter pw = new PrintWriter(new FileWriter(OutputCfgFilePath));

            // Write AlgorithmParameters, Signature and Encrypted Symmetric Key to config file
            pw.println(new String(Base64.getEncoder().encode(keyEncrypted)));
            pw.println(new String(Base64.getEncoder().encode(algParams.getEncoded())));
            pw.println(new String(Base64.getEncoder().encode(sigArray)));

            // Close Writer
            pw.close();

            // Success Message
            System.out.println(InputFilePath + " has been successfully encrypted to " + OutputFilePath);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
