import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Decrypt {
    public static void main(String[] args) {

        if (args.length < 1) {
            System.out.println("Usage:java Decrypt password");
            return;
        }

        // Initialize parameters
        char[] password = args[0].toCharArray();
        String SymmetricKeyEncryption = "AES";
        String KeyStoreImplementation = "JKS";
        String DataCipherTransformation = "AES/CBC/PKCS5Padding";
        String ConfigCipherTransformation = "RSA/ECB/PKCS1Padding";
        String SignatureAlgorithm = "SHA256withRSA";
        String KeyStoreFilePath = "keystoreB.jks";
        String KeyStoreAlias = "keyB";
        String KeyStoreSourceAlias = "keyA";
        String InputFilePath = "encrypted.txt";
        String OutputFilePath = "decrypted.txt";
        String InputCfgFilePath = "encrypted.cfg.txt";

        try {
            // Load KeyStore using password from argument
            FileInputStream fin = new FileInputStream(KeyStoreFilePath);
            KeyStore keyStore = KeyStore.getInstance(KeyStoreImplementation);
            keyStore.load(fin, password);

            // Retrieve Private Key from KeyStore
            PrivateKey prvKey = (PrivateKey) keyStore.getKey(KeyStoreAlias, password);

            // Initialize Cipher to decrypt config file
            Cipher cipher = Cipher.getInstance(ConfigCipherTransformation);
            cipher.init(Cipher.DECRYPT_MODE, prvKey);

            // Initialize Reader for config file
            BufferedReader br = new BufferedReader(new FileReader(InputCfgFilePath));

            // Retrieve symmetric key from config file
            byte[] keyArray = Base64.getDecoder().decode(br.readLine());
            byte[] dSymmetricKey = cipher.doFinal(keyArray);
            SecretKey symmetricKey = new SecretKeySpec(dSymmetricKey, 0, dSymmetricKey.length, SymmetricKeyEncryption);

            // Retrieve AlgorithmParameters from config file
            byte[] AlgParamsArray = Base64.getDecoder().decode(br.readLine());
            AlgorithmParameters algParams = AlgorithmParameters.getInstance(SymmetricKeyEncryption);
            algParams.init(AlgParamsArray);

            // Retrieve Signature from config file
            byte[] sigArray = Base64.getDecoder().decode(br.readLine());

            // Close Reader
            br.close();

            // Reinitialize Cipher for encrypted file
            cipher = Cipher.getInstance(DataCipherTransformation);
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey, algParams);

            // Initialize File Stream for encrypted file
            FileInputStream fis = new FileInputStream(InputFilePath);
            StringBuilder encryptedData = new StringBuilder();

            // Read encrypted data and store in byte[]
            byte[] b = new byte[8];
            int i;

            while ((i = fis.read(b)) != -1) {
                encryptedData.append(new String(b, 0, i));
            }

            byte[] encryptedBytes = encryptedData.toString().getBytes();

            // Retrieve Source Public Key from KeyStore
            PublicKey pubKeySource = keyStore.getCertificate(KeyStoreSourceAlias).getPublicKey();

            // Verify data integrity using Signature
            Signature sig = Signature.getInstance(SignatureAlgorithm);
            sig.initVerify(pubKeySource);
            sig.update(encryptedBytes);

			// Initialize File Stream for output file
            FileOutputStream fos = new FileOutputStream(OutputFilePath);

            if (sig.verify(sigArray)) {
				// Case where signature is verified
				// Initialize Cipher Stream to decrypt data and write to file
				fis = new FileInputStream(InputFilePath);
				CipherInputStream cis = new CipherInputStream(fis, cipher);
				
                while ((i = cis.read(b)) != -1) {
                    fos.write(b, 0, i);
                }
				
				// Close Input Streams
				cis.close();
				fis.close();
            }
            else {
				// Case where signature isn't verified
				// Write error message to file and cmd
                String message = "File has been tampered.";
                fos.write(message.getBytes());
				
                throw new Exception(message);
            }

            // Close Output Stream
            fos.close();

            // Success Message
            System.out.println(InputFilePath + " has been successfully decrypted to " + OutputFilePath);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
