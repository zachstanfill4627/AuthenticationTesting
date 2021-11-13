import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Hex;

public class AuthenticationTesting {

	public static void main(String[] args) {
		Scanner scnr = new Scanner(System.in);
		int option = 0;
		boolean end = false;
		
		String email = "";
		String password = "";
		String salt = "";
		
        int iterations = 10000;
        int keyLength = 512;
        
        User user = new User();
        
        System.out.println("Creating User Account");
        System.out.printf("\tEnter Email Address:   ");
		email = scnr.nextLine();
		System.out.printf("\tEnter Password:   ");
		password = scnr.nextLine();
       
		if(isValidPassword(password)) {
			salt = generateSaltKey();
			
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = salt.getBytes();
            
            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
            String hashedString = Hex.encodeHexString(hashedBytes);
            
            user = new User(email, hashedString, salt);
            
            System.out.printf("User Created Successfully\n\n");
        } else {
        	System.err.println("Password is Invalid\n\n");
        	end=true;
        }
        
        while (!end) {
			email = "";
			password = "";
			salt = "";
			
			System.out.printf("Select an option: \n"
					+ "\t1. Test Authentication into User Account\n"
					+ "\t2. Change Password\n"
					+ "\t3. End Authentication Testing\n\n"
					+ "Please make Selection: ");
			option = scnr.nextInt();
			scnr.nextLine();
			
		if (option == 1) {
				System.out.printf("\nEnter Password:   ");
				password = scnr.nextLine();
				
				salt = user.getSalt();
				
			    char[] passwordChars = password.toCharArray();
	            byte[] saltBytes = salt.getBytes();
	            
	            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
	            String hashedString = Hex.encodeHexString(hashedBytes);
	            
	            if(hashedString.equals(user.getPassword())) { 
	            	System.out.printf("\n\nAuthentication Success!\n\n");
	             } else {
	            	System.err.printf("\n\nAuthentication Failed!\n\n"); 
	             }
			} else if (option == 2) {
				System.out.printf("\nEnter Password:   ");
				password = scnr.nextLine();
		       
				if(isValidPassword(password)) {
					salt = generateSaltKey();
					
		            char[] passwordChars = password.toCharArray();
		            byte[] saltBytes = salt.getBytes();
		            
		            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
		            String hashedString = Hex.encodeHexString(hashedBytes);
		            
		            user.setPassword(hashedString);
		            user.setSalt(salt);
		            
		            System.out.println("User Password Updated Successfully\n\n");
		        } else {
		        	System.err.println("Password is Invalid and Wasn't Updated!\n\n");
		        }				
			} else if (option == 3) {
				end = true;
			} else {
				System.err.println("Invalid User Input, Please Try Again!\n\n");
			}
		} 
        
        scnr.close();
	}

    /**
     * Method to check if password is valid or not.
     * @param password
     * @return boolean
     */
    public static boolean isValidPassword(String password) {
    	String propertiesFile = "config/application.properties";
    	
    	/** Default Password Policy Values */
    	int minLength = 8;
    	int maxLength = 24;
    	int charClasses = 4;
    	int minCharClass = 0;
    	
    	/** Read Configured Properties */
    	try (InputStream input = new FileInputStream(propertiesFile)) {
            Properties prop = new Properties();
            prop.load(input);
            
            
            if(prop.getProperty("password.minLength") != null) {
            	minLength = Integer.parseInt(prop.getProperty("password.minLength"));
            }
            if(prop.getProperty("password.maxLength") != null) {
            	maxLength = Integer.parseInt(prop.getProperty("password.maxLength"));
            }
            if(prop.getProperty("password.charClasses") != null) {
            	charClasses = Integer.parseInt(prop.getProperty("password.charClasses"));
            }
            if(prop.getProperty("password.minCharClass") != null) {
            	minCharClass = Integer.parseInt(prop.getProperty("password.minCharClass"));
            }

            /** Validate Password Parameters */
            if(minLength < 0 || minLength > maxLength) {
            	System.err.println("Invalid password.minLength ; Setting Value to 8.");
            	minLength = 8;
            }
            if((maxLength > 50)) {
            	System.err.println("Invalid password.maxLength ; Setting Value to 24.");
            	maxLength = 24;
            }
            if(!(charClasses >= 1 && charClasses <= 4)) {
            	System.err.println("Invalid password.charClasses ; Setting Value to 4.");
            	charClasses = 4;	
            }
            if((charClasses*minCharClass) > maxLength) {
        		System.err.println("Invalid password.minCharClass ; Setting Value to 0");
        		minCharClass = 0;	
        	}    
    	} catch (IOException io) {
    		io.printStackTrace();
    	}
    	
    	
    	/** Verify the password length is within the specified parameters */
    	if (password.length() < minLength || password.length() > maxLength) {
    		System.err.println("Invalid Password Length");
    		return false;
    	}
    	
    	/** Initialize Counter Variables */
		int upper = 0, lower = 0, number = 0, special = 0;
		
		/** Initialize Available Special Characters for use in Passwords */
		String specialCharacters = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
		ArrayList<Character>specChar = new ArrayList<Character>();
		for(int c = 0; c < specialCharacters.length(); c++) { 
			specChar.add(specialCharacters.charAt(c));
		}

		/** Count Character Classes */
		for(int c = 0; c < password.length(); c++) { 
			if (password.charAt(c) >= 'A' && password.charAt(c) <= 'Z') { upper++; }
			else if (password.charAt(c) >= 'a' && password.charAt(c) <= 'z') { lower++; }
			else if (password.charAt(c) >= '0' && password.charAt(c) <= '9') { number++; }
			else if (specChar.indexOf(password.charAt(c)) > -1) { special++; }
		}
		
		/** Validate Password Meets Parameters */
		if(charClasses == 1) {
			if(upper > 0 || lower > 0 || special > 0) {
				System.err.println("Invalid Password Characters. Password can only contain Numbers [0-9].");
				return false;
			} else if (!(number >= minCharClass)) {
				System.err.println("Password does not contain the Minimum Number of Characters from the Number [0-9] Character Class.");
				return false;
			}
		} else if (charClasses == 2 ) {
			if(number > 0 || special > 0) {
				System.err.println("Invalid Password Characters. Password can only contain Alphabetic Characters [a-zA-Z].");
				return false;
			} else if (!(upper >= minCharClass && lower >= minCharClass)) {
				System.err.println("Password does not contain the Minimum Number of Characters from each Character Class.");
				return false;
			}
		} else if (charClasses == 3 ) {
			if(special > 0) {
				System.err.println("Invalid Password Characters. Password can only contain Alphanumeric Characters [a-zA-Z0-9].");
				return false;
			} else if (!(upper >= minCharClass && lower >= minCharClass && number >= minCharClass)) {
				System.err.println("Password does not contain the Minimum Number of Characters from each Character Class.");
				return false;
			}
		} else if (charClasses == 4 ) {
			if(!(upper >= minCharClass && lower >= minCharClass && number >= minCharClass && special >= minCharClass)) {
				System.err.println("Password does not contain the Minimum Number of Characters from each Character Class.");
				System.err.printf("\tUpper: %d\n\tLower: %d\n\tNumbers: %d\n\tSpecial: %d\n", upper, lower, number, special);
				return false;
			}
		}
			
        return true;
    }
    
	/**
	 * 
	 * @return salt key
	 */
	public static String generateSaltKey() {
	    int leftLimit = 48; // numeral '0'
	    int rightLimit = 122; // letter 'z'
	    int targetStringLength = 32;
	    Random random = new Random();

	    String salt = random.ints(leftLimit, rightLimit + 1)
	      .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
	      .limit(targetStringLength)
	      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
	      .toString();
	    
	    return salt;
	}


    /**
     * Hash Password
     * @param password
     * @param salt
     * @param iterations
     * @param keyLength
     * @return
     */
    public static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) {

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
            SecretKey key = skf.generateSecret( spec );
            byte[] res = key.getEncoded( );
            return res;
        } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
        }
    }
	
}
