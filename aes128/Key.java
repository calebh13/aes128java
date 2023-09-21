package aes128;

public class Key extends ByteMatrix
{
    private int[][] roundKeyWords = new int[44][4];
    
    public Key(byte[] key)
    {
        // Note that the hash simply gets trimmed when converting to 4x4 byte matrix
        super(key);
        expandKey();
    }
    
    public Key(String key) // overloaded constructor for debug purposes
    {
        super(key);
        expandKey();
    }
    
    private void expandKey()
    {
        /* This is key expansion, where we turn the key into a
         * key schedule composed of round keys. A round key is 4 words.
         * Words w4 w5 w6 w7 = round key for round 1 for example. */
        
        int[] roundConstants = genRoundConstants();
            
        int[] temp = new int[4];
        for(int i = 0; i < 44; i++)
        {
            if(i < 4)
            {
                // initial state array words
                temp = this.getWord(i);
                for(int j = 0; j < 4; j++)
                {
                    roundKeyWords[i][j] = temp[j];
                }
            } else
            {
                // w4 = w0 XOR g(w3) (every fourth word is special)
                // w5 = w4 XOR w1, w6 = w5 XOR w2, etc.
                if(i % 4 == 0)
                {
                    temp = xor(getWord(roundKeyWords, i - 4), g(getWord(roundKeyWords, i - 1), roundConstants[i / 4 - 1]));
                    for(int j = 0; j < 4; j++)
                    {
                        roundKeyWords[i][j] = temp[j];   
                    }
                } else
                {
                    // w5 = w4 XOR w1, w6 = w5 XOR w2, etc
                    temp = xor(getWord(roundKeyWords, i - 4), getWord(roundKeyWords, i - 1));
                    for(int j = 0; j < 4; j++)
                    {
                        roundKeyWords[i][j] = temp[j];
                    }
                }
            }
        }   
    }
    
    public int[] getRoundKeyWord (int wordNum)
    {
        // wordNum is a number from 0 to 43
        int[] word = {roundKeyWords[wordNum][0], roundKeyWords[wordNum][1], roundKeyWords[wordNum][2], roundKeyWords[wordNum][3]};
        return word;
    }
    
    public static int[] genRoundConstants()
    {
        int[] roundConstants = new int[10];
        roundConstants[0] = 1;
        roundConstants[1] = 2;
        for(int i = 2; i < 10; i++)
        {
            roundConstants[i] = Poly.polyMult(2, roundConstants[i - 1], 283);   
        }
        
        return roundConstants;
    }
    
    public static int[] g(int[] word, int roundConstant)
    {
        // This is the g() function defined in NIST specifications
        int[] w = {Poly.enc_sbox[word[1]] ^ roundConstant, Poly.enc_sbox[word[2]], Poly.enc_sbox[word[3]], Poly.enc_sbox[word[0]]};
        return w;
    }
    
    public int[] xor(int[] a, int[] b)
    {
        int[] x = {a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]};
        return x;
    }
}
