// project created on 3/27/2007 at 6:58 PM
using System;
using Rjl.MyPW;
namespace mypwtest
{
	class MainClass
	{
		public static void Main(string[] args)
		{
    		Console.WriteLine("================================");
    		Console.WriteLine("Testing MyPWAuthenticator with the test values");
    		Console.WriteLine();
    		
    		MyPWAuthenticator auth = new MyPWAuthenticator("10e54f8f91c797c939e524bdd033b4f6");
    	    
    		auth.SetAuthKey("5f8dc349a51bf7a2f429e2a4dda308ee");
			auth.SetSiteID("test");
			auth.SetToken("9999", "123456");
			auth.SetUserIP("127.0.0.1");
			auth.SetNote("This is my note to pass to MyPW");
	
			Console.WriteLine("Auth Code: " + auth.Authenticate());
			Console.WriteLine("Validated: " + auth.Validate());
			Console.WriteLine();
			auth.DisplayResults();
		}			
	}
}