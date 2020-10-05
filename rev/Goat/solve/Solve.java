/* 
Program Name: Solve.java
Author: TSBloxorz
Description: The solve file for RE chall: Goat */

import java.util.Random;

public class Solve {
	public static void main(String[] args) {
		/* To solve the chall, we can take a look at the source code. We see that the source code
		is comparing our input to the number below, so we can copy that in */
		String flag = "97.122.54.50.93.66.99.117.75.51.101.78.104.119.90.53.94.36.102.84.40.69.";

		/* These look like ASCII values with dots in between them.
		Let's seperate them into an array and get the integer values */
		String temp = "";
		int[] flag2 = new int[flag.length()];
		int flag2Index = 0;
		for (int i = 0; i < flag.length(); i++) {
			if (flag.charAt(i) != '.') {
				temp += flag.charAt(i);
			} else {
				int temp2 = Integer.valueOf(temp);
				flag2[flag2Index++] = temp2;
				temp = "";
			}
		}
		/*Work Backwards from CrackMe.java (source code). We start by XORing
		How to reverse XOR, written as ^:
			a ^ b = c
			a ^ c = b
			b ^ c = a
		*/
		Random r = new Random(); 
		r.setSeed(431289); //We choose the same seed to ensure that we get the same Random Values
		int[] flag3 = new int[flag2Index];
		for(int i = 0; i < flag3.length; i++) {
			flag3[i] = (int)flag2[i] ^ r.nextInt(i+1);
		} 
		
		/* We then see that in the source code, the numbers are getting swapped with 
		the numbers in f array. To reverse this, we can create a new array called x, 
		which stores the indices of the correct indices */

        //         0   1   2   3  4  5  6   7   8   9  10  11  12 13 14 15 16  17 18  19  20  21				
		int[] f = {19, 17, 15, 6, 9, 4, 18, 8, 16, 13, 21, 11, 7, 0, 12, 3, 5, 2, 20, 14, 10, 1};
		int[] x = {13, 21, 17, 15, 5, 16, 3, 12, 7, 4, 20, 11, 14, 9, 19, 2, 8, 1, 6, 0, 18, 10};
		int[] flag4 = new int[flag3.length];
        for (int i = flag3.length-1; i >= 0; i--) { 
            flag4[i] = flag3[x[i]];
        } 
	    

        /* Lastly, the swap is simply swapping the first and last elements,
        which we can easily perform. */
        for (int i = 0; i < flag4.length / 2; i++) {
			int temp4 = flag4[flag4.length - i - 1];
			flag4[flag4.length - i - 1] = flag4[i];
			flag4[i] = temp4;
		}

		/* Because we have been working with integer values the whole time,
		we want to convert back to char values so we can see the flag! */
        for (int i = 0; i < flag4.length; i++) {
        	System.out.print((char)flag4[i]);
        } 
		System.out.println();

	}
}
