package aes128;
public abstract class ByteMatrix
{
    private int[][] arr = new int[4][4];
    
    public ByteMatrix(String str) // str must be in hex
    {
        // hexArr is an array of Strings which have 2 hex digits
        // 2 hex digits = 1 byte, which is very convenient

        // splits into 2 characters
        String[] hexArr = str.split("(?<=\\G.{" + 2 + "})");
        
        /* AES is Column Major: e.g. [j][i]
         * byte0 byte4 byte8  byte12
         * byte1 byte5 byte9  byte13
         * byte2 byte6 byte10 byte14
         * byte3 byte7 byte11 byte15
         */
         
         // AES also has the notion of a word, which is 1 column.
         // For example, word 0 would include byte0, 1, 2, and 3.
        
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                // convert hex string into an actual integer
                arr[j][i] = new Integer(Integer.parseInt(hexArr[i * 4 + j], 16));                
            }
        }
    }
    
    public ByteMatrix(byte[] bytes)
    {
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                arr[j][i] = Byte.toUnsignedInt(bytes[i * 4 + j]);
            }
        }
    }
    
    public int[][] getArr()
    {
        return this.arr;   
    }
       
    public int[] getWord(int i)
    {
        int[] word = {arr[0][i], arr[1][i], arr[2][i], arr[3][i]};
        return word;
    }
    
    public int[] getWord(int[][] a, int word) // For any 2d array e.g. roundKeyWords
    {
        int[] temp = {a[word][0], a[word][1], a[word][2], a[word][3]};
        return temp;
    }
    
    public int getByte(int i, int j)
    {
        return arr[i][j];
    }
    
    public byte getByteAsByte(int i, int j)
    {
        return (byte)arr[i][j];   
    }
    
    public void setByte(int i, int j, int val)
    {
        arr[i][j] = val;
    }
    
    public String toHexString()
    {
        String str = "";
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                String temp = Integer.toString(arr[j][i], 16);
                if(temp.length() == 1)
                {
                    str += "0" + temp;   
                } else
                {
                    str += temp;   
                }
            }
        }
        return str;
    }    
}
