/* In order to fully understand this program, you should read the official AES
specifications on NIST here: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

Also note that the encrypt() method in this AES128 class uses CBC mode 
and PKCS#7 padding. So results will not match up with the appendices on the
NIST site, unless you use the encryptNoCBC functions by entering a -1. Please read all comments :)

When reading the hex output, though, don't forget that AES is column-major
and the example state arrays need to be read in that way. 

Furthermore, this program uses no precomputed lookup tables. 
Everything is generated algorithmically. */

package aes128;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner; 
public class AES128 {

    public static void main(String[] args) 
		{
				Scanner s = new Scanner(System.in);
        String pass, enc;
        // Set verboseMode to true to print every step of encryption.
        // Put -1 into the prompt to get the results that match up with Appendix B on NIST site, linked above.
        boolean verboseMode = false;
        System.out.print("Enter 0 to encrypt, or 1 to decrypt: ");
        int x = s.nextInt();
        s.nextLine();
        switch(x) 
				{
            case 1:
                // Note: all valid UTF-8 characters work!
                System.out.print("Enter encrypted text: ");
                String ciphertext = s.nextLine();
                System.out.print("Enter your password: ");
                pass = s.nextLine();
                System.out.println("Decrypted text: " + decrypt(ciphertext, genKey(pass), verboseMode));
                break;
            case -1:
                // Check out Appendix B on the linked NIST site (page 38)
                System.out.println("Remember that AES state arrays are read in a column-major order.");
                String key = "2b7e151628aed2a6abf7158809cf4f3c";
                String in = "3243f6a8885a308d313198a2e0370734";
                enc = encryptNoCBC(in, key, true);
                System.out.println("\n\n=====DECRYPTION=====\n\n");
                String dec = decryptNoCBC(enc, key, true);
                System.out.println(dec);
                break;
            default:
                System.out.print("Enter text to encrypt: ");
                String plaintext = s.nextLine();
                System.out.print("Enter your password: ");
                pass = s.nextLine();
                enc = encrypt(plaintext, genKey(pass), verboseMode);
                System.out.println("Encrypted text: " + enc);
                // Just to prove that decryption works:
                System.out.println("Decrypted text: " + decrypt(enc, genKey(pass), verboseMode));
                break;
        }
    }
    
    public static Key genKey(String pass)
    {
        double start = System.currentTimeMillis();
        MessageDigest md = null;
        try 
        {
            md = MessageDigest.getInstance("SHA-256");
        } catch(NoSuchAlgorithmException e) {}
        byte[] hash = md.digest(pass.getBytes(Charset.forName("UTF-8")));
        for(int i = 0; i < 100000; i++)
        {
            hash = md.digest(hash); // sha-256 hash iterated 100k times
        }
        
        Key key = new Key(hash);
        double end = System.currentTimeMillis();
        System.out.println("Key schedule generated in " + (end - start) / 1000 + "s");
        return key;
    }
    
    public static String encryptNoCBC(String plaintext, String pass, boolean verboseMode)
    {
        // This function has no sanity checks! May crash with invalid input
        StateArray sa = new StateArray(plaintext);
        Key key = new Key(pass);
        if(verboseMode)
        {
            sa.encryptVerbose(key);   
        } else
        {
            sa.encrypt(key);
        }
        return sa.toHexString();
    }
    
    public static String decryptNoCBC(String ciphertext, String pass, boolean verboseMode)
    {
        // Again, no sanity checks.
        StateArray sa = new StateArray(ciphertext);
        Key key = new Key(pass);
        if(verboseMode)
        {
            sa.decryptVerbose(key);   
        } else
        {
            sa.decrypt(key);   
        }
        return sa.toHexString();
    }
    
    public static String encrypt(String plaintext, Key key, boolean verboseMode)
    {        
        /* This mode of encryption is known as cipher block chaining. We have
         * our actual method of encryption, AES, but that only works on exactly
         * 4x4 arrays of bytes. To allow for longer messages, we use CBC mode. The
         * first block (4x4 array) of plaintext is XORed with a randomly generated
         * "initialization vector" (IV), which makes it so that, if you have the exact same block
         * encrypted with the same password, it's not identitcal. After the XOR, the
         * block is encrypted using AES. That resulting ciphertext is then XORed with the
         * next block of plaintext, and so on until we reach the end of our plaintext.
         * It's much more secure than individually encrypting each block.*/
        
        byte[] utf8 = plaintext.getBytes(Charset.forName("UTF-8"));
        // utf-8 is luckily fully supported in java, so no need to manually encode/decode

        int numBlocks = utf8.length / 16 + 1;
        int toPad = (numBlocks * 16) - utf8.length;

        // Now to turn the string of plaintext into an array of state arrays
        StateArray[] allBlocks = new StateArray[numBlocks + 1]; // + 1 because of IV
        String temp = "";
        for(int i = 0; i < numBlocks; i++)
        {
            for(int j = 0; j < 16; j++)
            {
                // If all plaintext has been added to the state arrays and it does not perfectly fill a 4x4 array
                if(toPad != 0 && (i * 16 + j) >= utf8.length)
                {
                    // PKCS#7 padding
                    // E.g. if 10 chars to pad, pad with "0A", if 9, "09", etc
                    // Hexadecimal works nicely for this because there are 16 chars
                    String paddingChar = Integer.toString(toPad, 16);
                    
                    if(paddingChar.length() == 1)
                    {
                        // prefix 0 so that it becomes 08 instead of just 8
                        // otherwise there would not be 8 8's
                        temp += "0" + paddingChar;
                    } else
                    {
                        temp += paddingChar;   
                    }
                // If there still is plaintext to add, add it as a hex string
                // The ByteMatrix class just needs things to be in hex to work properly
                } else 
                {
                    temp += Integer.toString(Byte.toUnsignedInt(utf8[i * 16 + j]), 16);
                }                    
            }
            allBlocks[i + 1] = new StateArray(temp);
            temp = "";
        }
                
        // here we generate the initialization vector and prefix it
        // to the state arrays
        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[16];
        rand.nextBytes(iv);
        allBlocks[0] = new StateArray(iv);
                
        // now begin CBC rounds - this is the "meat" of the process
        for(int i = 1; i < allBlocks.length; i++)
        {
            allBlocks[i].xor(allBlocks[i - 1]);
            if(verboseMode)
            {
                allBlocks[i].encryptVerbose(key);   
            } else
            {
                allBlocks[i].encrypt(key);   
            }
        }
        
        String str = "";
        for (StateArray block : allBlocks) {
            str += block.toHexString();
        }
                
        return str;
    }
    
    public static String decrypt(String ciphertext, Key key, boolean verboseMode)
    {
        // Because it's hex, 32 characters = 16 bytes
        int numBlocks = ciphertext.length() / 32;
        if(numBlocks < 2) // remember initialization vector is 1st block
        {
            System.out.println("ERROR: Invalid ciphertext length.");
            return null;
        }
        StateArray[] allBlocks = new StateArray[numBlocks];
        for(int i = 0; i < numBlocks; i++)
        {
            allBlocks[i] = new StateArray(ciphertext.substring(32 * i, 32 * (i + 1)));
        }
        StateArray[] copy = new StateArray[numBlocks];
        
        for(int i = 0; i < numBlocks; i++)
        {
            // uses String constructor of StateArray
            copy[i] = new StateArray(allBlocks[i].toHexString());
        }
        
        // byte array temp is the array of UTF-8 bytes, and will be
        // decoded into characters after decryption. unfortunately, in java the utf-8 MUST
        // be stored in a byte[]
        byte[] temp = new byte[16 * (numBlocks - 1)]; // does not include IV
        
        for(int i = 1; i < numBlocks; i++)
        {
            // this is where the actual decryption happens
            if(verboseMode)
            {
                allBlocks[i].decryptVerbose(key);   
            } else
            {
                allBlocks[i].decrypt(key);   
            }
            allBlocks[i].xor(copy[i - 1]); // remember it's CBC mode; note that allBlocks still has IV
            for(int j = 0; j < 4; j++)
            {
                for(int k = 0; k < 4; k++)
                {
                    // we need j and k in order to access the individual bytes of
                    // the state array in allBlocks
                    // temp[block num * 16 + (byte of state array)]
                    // this copies all UTF8 into temp[] so it can be deCODED (not decrypted)
                    temp[(i - 1) * 16 + (j * 4 + k)] = allBlocks[i].getByteAsByte(k, j);
                }
            }
        }
        // this checks if the padding is valid - otherwise something was wrong with key or ciphertext
        if(temp.length - Byte.toUnsignedInt(temp[temp.length - 1]) < 0)
        {
            System.out.println("ERROR: Invalid ciphertext.");
            return null;
        }
        // previously we could not know the exact length of the byte array
        // because it still had padding characters. it needs to be the exact
        // length for the java conversion method, so we make a new byte[]
        byte[] utf8 = new byte[temp.length - Byte.toUnsignedInt(temp[temp.length - 1])];
        for(int i = 0; i < utf8.length; i++)
        {
            utf8[i] = temp[i];
        }
        // obscure usage of the String constructor to decode
        String decoded = new String(utf8, Charset.forName("UTF-8"));
        
        return decoded;
    } 
}
