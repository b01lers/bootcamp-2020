import java.util.Random;
import java.util.Scanner;

public class CrackMe {
	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		System.out.println("What is the flag?");
		String flag = sc.nextLine();
		if (flag.length() != 22) {
			System.out.println("Not the flag :(");
			return;
		}
		char[] flag2 = new char[flag.length()];
		for (int i = 0; i < flag.length(); i++) {
			flag2[i] = flag.charAt(i);
		}
		for (int i = 0; i < flag.length() / 2; i++) {
			char temp = flag2[flag.length() - i - 1];
			flag2[flag.length() - i - 1] = flag2[i];
			flag2[i] = temp;
		}
		int[] f = {19, 17, 15, 6, 9, 4, 18, 8, 16, 13, 21, 11, 7, 0, 12, 3, 5, 2, 20, 14, 10, 1};
		int[] flag4 = new int[flag2.length];
        for (int i = f.length-1; i >= 0; i--) { 
            flag4[i] = flag2[f[i]];
        } 
	    

        Random r = new Random(); 
        r.setSeed(431289);
        int[] flag3 = new int[flag.length()];
		for(int i = 0; i < flag.length(); i++) {
			flag3[i] = (int)flag4[i] ^ r.nextInt(i+1);
		} 

		String yourFlag = "";
		for (int i = 0; i < flag3.length; i++) {
			yourFlag += flag3[i] + ".";
		}
		if (yourFlag.equals("97.122.54.50.93.66.99.117.75.51.101.78.104.119.90.53.94.36.102.84.40.69.")) {
			System.out.println("Congrats! You got the flag!");
		} else {
			System.out.println("Not the flag :(");
		} 
		
	}
} //KEEP SCROLLING DOWN FOR FLAG :)

























































































































































































































































































































































































































































/*
   ____           _            _               _   _ 
  / ___|   ___   | |_    ___  | |__     __ _  | | | |
 | |  _   / _ \  | __|  / __| | '_ \   / _` | | | | |
 | |_| | | (_) | | |_  | (__  | | | | | (_| | |_| |_|
  \____|  \___/   \__|  \___| |_| |_|  \__,_| (_) (_)
*/
