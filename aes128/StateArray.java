package aes128;

public class StateArray extends ByteMatrix
{    
    public StateArray(String cleartext)
    {
        super(cleartext);
    }
    
    public StateArray(byte[] bytes)
    {
        super(bytes);   
    }
    
    public void encrypt(Key key)
    {
        for(int i = 0; i < 9; i++)
        {
            addRoundKey(key, i);
            subBytes();
            shiftRows();
            mixColumns();
        }
        addRoundKey(key, 9);
        subBytes();
        shiftRows();
        addRoundKey(key, 10);
    }
    
    public void encryptVerbose(Key key)
    {
        System.out.println("Input: " + this.toHexString());
        for(int i = 0; i < 9; i++)
        {
            System.out.println("Round " + (i + 1) + ": ");
            addRoundKey(key, i);
            System.out.println(this.toHexString());
            subBytes();
            System.out.println(this.toHexString());
            shiftRows();
            System.out.println(this.toHexString());
            mixColumns();
            System.out.println(this.toHexString());
        }
        System.out.println("Round 10: ");
        addRoundKey(key, 9);
        System.out.println(this.toHexString());
        subBytes();
        System.out.println(this.toHexString());
        shiftRows();
        System.out.println(this.toHexString());
        addRoundKey(key, 10);
        System.out.println("Output: " + this.toHexString());
    }
    
    public void decrypt(Key key)
    {
        addRoundKey(key, 10);
        for(int i = 9; i > 0; i--)
        {
            invShiftRows();
            invSubBytes();
            addRoundKey(key, i);
            invMixColumns();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(key, 0);
    }
    
    public void decryptVerbose(Key key)
    {
        addRoundKey(key, 10);
        for(int i = 9; i > 0; i--)
        {
            System.out.println("Round " + i + ": ");
            invShiftRows();
            System.out.println(this.toHexString());
            invSubBytes();
            System.out.println(this.toHexString());
            addRoundKey(key, i);
            System.out.println(this.toHexString());
            invMixColumns();
            System.out.println(this.toHexString());
        }
        System.out.println("Round 0: ");
        invShiftRows();
        System.out.println(this.toHexString());
        invSubBytes();
        System.out.println(this.toHexString());
        addRoundKey(key, 0);
        System.out.println("Output: " + this.toHexString());
    }
    
    public void xor(StateArray s)
    {
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                setByte(i, j, getByte(i, j) ^ s.getByte(i, j));
            }
        }
    }
    
    public void addRoundKey(Key key, int roundNum)
    {
        // Round 0 uses words 0 1 2 3 from key schedule
        // Round 10 uses 40 41 42 43
        int[] temp = new int[4];
        for(int i = 0; i < 4; i++)
        {
            temp = key.getRoundKeyWord(roundNum * 4 + i);
            for(int j = 0; j < 4; j++)
            {
                setByte(j, i, this.getByte(j, i) ^ temp[j]);
            }
        }
    }
    
    public void subBytes()
    {
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                setByte(i, j, Poly.enc_sbox[getByte(i, j)]);   
            }
        }
    }
    
    public void invSubBytes()
    {
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                setByte(i, j, Poly.dec_sbox[getByte(i, j)]);   
            }
        }
    }
    
    public void shiftRows()
    {
        // first row is unchanged
        // second row shifted one byte left
        // third row shifted two bytes left
        // fourth row shifted three bytes
        
        int[][] temp = new int[4][4]; // need to make copy because of swaps
        
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                temp[i][j] = getByte(i, j);
            }
        }
        
        int index;
        for(int i = 1; i < 4; i++) // row
        {
            for(int j = 0; j < 4; j++) // byte
            {
                index = j + i;
                if(index > 3)
                {
                    index = (j + i) - 4; // wrap around
                }
                setByte(i, j, temp[i][index]);
            }
        }
    }
    
    public void invShiftRows()
    {
        int[][] temp = new int[4][4];
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                temp[i][j] = getByte(i, j);   
            }
        }
        
        int index;
        for(int i = 1; i < 4; i++) // row
        {
            for(int j = 0; j < 4; j++) // byte
            {
                index = j - i;
                if(index < 0)
                {
                    index = 4 + (j - i); // wrap around
                }
                setByte(i, j, temp[i][index]);
            }
        }
    }
    
    public void mixColumns()
    {
        // uses columns (words) and multiplies them
        // use lecture 8 for this, page 34
        
        // replaces each byte as a function of all other bytes in that COLUMN
        // each byte in a column is replaced by (c0) times
        // the byte below, XOR (c1) times the next, XOR (c2 times) the 
        // next, XOR (c3) times next byte.
        
        //       c0            c1            c2            c3
        // b0 = (02 * b0) XOR (03 * b4) XOR (01 * b8) XOR (01 * b12)
        
        /* coefficients:
         * c0 c1 c2 c3
         * 02 03 01 01 for bytes in row 1
         * 01 02 03 01 for bytes in row 2
         * 01 01 02 03 for bytes in row 3
         * 03 01 01 02 for bytes in row 4
         */
        
        
        int[][] temp = new int[4][4]; // need to make copy because of swaps
        
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                temp[i][j] = getByte(i, j);
            }
        }
                
        for(int col = 0; col < 4; col++)
        {
            setByte(0, col, Poly.polyMult(2, temp[0][col]) ^ Poly.polyMult(3, temp[1][col]) ^ temp[2][col] ^ temp[3][col]);
            setByte(1, col, temp[0][col] ^ Poly.polyMult(2, temp[1][col]) ^ Poly.polyMult(3, temp[2][col]) ^ temp[3][col]);
            setByte(2, col, temp[0][col] ^ temp[1][col] ^ Poly.polyMult(2, temp[2][col]) ^ Poly.polyMult(3, temp[3][col]));
            setByte(3, col, Poly.polyMult(3, temp[0][col]) ^ temp[1][col] ^ temp[2][col] ^ Poly.polyMult(2, temp[3][col]));
        }
    }
    
    public void invMixColumns()
    {
        // same algorithm as regular mixColumns except different coefficients
        
        int[][] temp = new int[4][4];
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                temp[i][j] = getByte(i, j);
            }
        }
        
        for(int col = 0; col < 4; col++)
        {
            // 0x0e
            setByte(0, col, Poly.polyMult(0x0e, temp[0][col]) ^ Poly.polyMult(0x0b, temp[1][col]) ^ Poly.polyMult(0x0d, temp[2][col]) ^ Poly.polyMult(0x09, temp[3][col]));
            setByte(1, col, Poly.polyMult(0x09, temp[0][col]) ^ Poly.polyMult(0x0e, temp[1][col]) ^ Poly.polyMult(0x0b, temp[2][col]) ^ Poly.polyMult(0x0d, temp[3][col]));
            setByte(2, col, Poly.polyMult(0x0d, temp[0][col]) ^ Poly.polyMult(0x09, temp[1][col]) ^ Poly.polyMult(0x0e, temp[2][col]) ^ Poly.polyMult(0x0b, temp[3][col]));
            setByte(3, col, Poly.polyMult(0x0b, temp[0][col]) ^ Poly.polyMult(0x0d, temp[1][col]) ^ Poly.polyMult(0x09, temp[2][col]) ^ Poly.polyMult(0x0e, temp[3][col]));
        }
    }
}
