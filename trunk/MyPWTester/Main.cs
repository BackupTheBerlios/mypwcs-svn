// project created on 3/27/2007 at 6:58 PM
// This is just meant to be a simple test of the MyPWAuthenticatorCS Class

using System;
using Rjl.MyPW;
namespace mypwtest
{
	class MainClass
	{
		public static void Main(string[] args)
		{
    		Console.WriteLine("MyPWAuthenticatorCS Test Application");
    		Console.WriteLine("Copyright 2007 by Robert J. Lawrence.  All rights reserved.");
    		Console.WriteLine();
    		Console.WriteLine("Test #1");
    		Console.WriteLine("    Sending a test authentication to MyPW using the test values listed on their");
    		Console.WriteLine("    developer website.  This should pass unless you are having connectivity"); 
    		Console.WriteLine("    problems or MyPW's servers are down for some reason.");
    		Console.WriteLine();
    		Console.WriteLine("*** Sending Test Data to MyPW ***");
    		Console.WriteLine();
    		
    		MyPWAuthenticator testauth = new MyPWAuthenticator("10e54f8f91c797c939e524bdd033b4f6");
    	    
    		testauth.SetAuthKey("5f8dc349a51bf7a2f429e2a4dda308ee");
			testauth.SetSiteID("test");
			testauth.SetToken("9999", "123456");
			testauth.SetUserIP("127.0.0.1");
			testauth.SetNote("This is my note to pass to MyPW");
	
			Console.WriteLine("Auth Code: " + testauth.Authenticate());
			Console.WriteLine("Validated: " + testauth.Validate());
			Console.WriteLine("Auth Message: " + testauth.GetResponseMessage());
			Console.WriteLine();

			Console.WriteLine("Test #2");
    		Console.WriteLine("    This is the interactive test.  You will be asked to enter the token id and");
    		Console.WriteLine("    the token value. These will be sent to MyPW. The results of the");
    		Console.WriteLine("    authentication will be shown.  You can enter 'quit' for token id to quit.");
    		Console.WriteLine();
    		Console.WriteLine("     Also, you can customize the source with your secret, siteid, and authkey");
    		Console.WriteLine("     to test with live data");
    		Console.WriteLine();
    		
  			string tokenid = "";
    		string tokenvalue = "";
    		bool quit = false;
  			
    		// To test with your info, change the following as:
    		//MyPWAuthenticator auth = new MyPWAuthenticator("YOUR_SECRET", "YOUR_AUTHKEY", "YOUR_SITEID");
    		MyPWAuthenticator auth = new MyPWAuthenticator("10e54f8f91c797c939e524bdd033b4f6", "5f8dc349a51bf7a2f429e2a4dda308ee", "test");
    		
    	    auth.SetSiteName("testsite");
    	 	auth.SetUserIP("127.0.0.1");
			auth.SetNote("This is my test note to pass to MyPW");
			
			while (quit == false) {
				Console.WriteLine("========================================");
				Console.Write("Enter your token ID (or 'quit' to quit): ");
				tokenid = Console.ReadLine();
			
				if (tokenid.ToLower() == "quit") {
					quit = true;
					
				} else {
					Console.Write("Enter your token value: ");
					tokenvalue = Console.ReadLine();
					Console.WriteLine();
			
					auth.SetToken(tokenid, tokenvalue);
					Console.WriteLine("*** Sending interactive data to MyPW ***");
			
					Console.WriteLine("Auth Code: " + auth.Authenticate());
					Console.WriteLine("Validated: " + auth.Validate());
					Console.WriteLine("Auth Message: " + auth.GetResponseMessage());
					Console.WriteLine();
				}
			}
		}			
	}
}