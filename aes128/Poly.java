package aes128;

public abstract class Poly
{
    public static final int[] enc_sbox = makeEncSubTable();
    public static final int[] dec_sbox = makeDecSubTable(enc_sbox);
    
    public static int[] makeEncSubTable()
    {
        double start = System.currentTimeMillis();
        int[] sTable = new int[256];
        sTable[0] = 0x63;
        for(int i = 1; i < 256; i++)
        {
            sTable[i] = polyMult(inverse(i), 31, 257) ^ 0x63;
        }
        double end = System.currentTimeMillis();
        System.out.println("S-table generated in " + (end - start) / 1000 + "s");
        return sTable;
    }
    
    public static int[] makeDecSubTable(int[] encTable)
    {
        int[] sTable = new int[256];
        for(int i = 0; i < 256; i++)
        {
            // This is just the inverse
            sTable[encTable[i]] = i;
        }
        return sTable;
    }
    
    public static int inverse(int x)
    {
        if(x == 0)
        {
            return 0;   
        }
        for(int i = 1; i < 256; i++)
        {
            // Multiplicative inverse is when x * y = 1.
            // In standard arithmetic, it's the reciprocal, but
            // because this is modular it functions much differently.
            if(polyMult(x, i) == 1)
            {
                return i;
            }
        }
        
        return 0;
    }
    
    
    public static int polyMult(int a, int b, int mod)
    {
        int prod = 0;
        for(int i = 0; i < 8; i++)
        {
            /* Let's say we want to multiply 2 polynomials. For example, 0x56 * 0x13.
             * This is equivalent to 0x56 * (0x02 ^ 0x10) where ^ is XORing. This is obvious by the binary representation
             * of 0x13: 00010010. In binary multiplication, multiplying by 0x02 is extremely convenient as it requires only a 
             * single left bitshift, and an XOR if the product is > 0xFF. So, by breaking the product down into bits, we can use
             * repeated multiplications of 2 to get each bit. For bit 0x02, we multiply by 2^1, for 0x10, we multiply by 2^4, etc.
             * Thus 0x56 * 0x13 = (0x57 * 2^1) ^ (0x57 * 2^4). The best way to figure out the number of times we should 
             * multiply by 2 is by using a bitmask each loop to get the value of each bit. The bitmask in the function below is
             * expressed in math notation as b & (2 ^ 7 - i). So for the fourth loop, we actually get the fourth bit from the left: 2^4 = 00010000.
             * 00001000 & 00010010 = 00001000 which as an integer is equivalent to 2^(3) = 8. Remember 0-indexing. Therefore, the BINARY log
             * of this bit is the number of times we should multiply by x (polynomial x = 2^1 in AES arithmetic). We don't take the binary
             * log here; that's instead implemented in the i *= 2 of the xtime function. So the xtime function will multiply 56 by 2 a total of 
             * 3 times, and return that result. This is XORed with the other products to get the final product, which is what polyMult returns. */
            
            prod ^= xtime(a, b & (int)Math.pow(2, 7 - i), mod);
        }
        return prod;
    }
    
    
    public static int polyMult(int a, int b)
    {
        // default modulus
        return polyMult(a, b, 0x11B);
    }
    
    public static int xtime(int b, int numOfTimes, int mod)
    {
        if(numOfTimes == 0)
        {
            return 0; // 0 * 0 = 0
        }
        int prod = b; // this is the bitmasked single bit
        // note that numOfTimes is a power of two, so the binary log is effectively implemented here with i *= 2
        for(int i = 1; i < numOfTimes; i *= 2) 
        {
            prod = prod << 1; // left bitshift
            if(prod > 0xFF) // if it's greater than a byte, return remainder XOR modulus
            {
                prod ^= mod;
            }
        }
        
        return prod;
    }
}
