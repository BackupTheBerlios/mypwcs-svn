/* MyPWAuthenticator is my attempt to create a new, easy to use DLL
 * that will allow me to utilize MyPW token authentication to any
 * Mono / .NET application.
 *
 * Copyright (c) 2007, Robert J. Lawrence
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY ROBERT J. LAWRENCE ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
  /* How to use (in order):
   *
   * 1. Instantiate a new MyPWAuthenticator
   * 2. Use SetAuthKey(), SetSiteID(), SetToken() [, SetSiteName(), 
   *    SetUserIP(), SetNote()] to define the data to send to MyPW
   * 3. Authenticate() - returns the code from MyPW
   * 4. Validate() - returns true if the calculated validate hash 
   *    matches the hash returned from MyPW
   * 5. Reset() - clears all the request data that regularly changes
   *    so that you can re-use the authenticator object
   */
  
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Nwc.XmlRpc;

namespace Rjl.MyPW
{
	
	///<summary>MyPW Authentication client library for Mono / .NET (2.0)</summary>
	///<remarks> </remarks>
	public class MyPWAuthenticator
	{
		// Class level data
		// This all should be private.  We only want to modify from the methods
		private Dictionary<string,string> request = new Dictionary<string,string>();  //XML RPC Request Data
		private Hashtable results;  // XML RPC Result Data
		
		private string secret;  // MyPW secret
		private string authkey; // MyPW authkey
		private string siteid;	// MyPW siteid
		
		///<summary>Default Constructor</summary>
		///<remarks>This constructor doesn't set the "secret".  Therefore
		///all attemtps to use <c>Validate()</c> will return false as the hash
		///can not be properly computed without the secret.</remarks>
		public MyPWAuthenticator() 
		{
			this.secret = "";
		}
		
		///<summary>Constructor</summary>
		///<remarks></remarks>
		///<param name="secret">The <c>secret</c> is the shared secret that is
		///used to compute the validation hash with <c>Validate()</c></param>
		public MyPWAuthenticator(string secret)
		{
			this.secret = secret;
		}
		
		///<summary>This constructor makes it easy to set all the standard, static info</summary>
		///<remarks></remarks>
		///<param name="secret">The <c>secret</c> is the shared secret that is
		///used to compute the validation hash with <c>Validate()</c></param>
		///<param name="authkey">The <c>authkey</c> used to authorize requests</param>
		///<param name="siteid">The <c>siteid</c> identifies you to MyPW</param>
		public MyPWAuthenticator(string secret, string authkey, string siteid)
		{
			this.secret = secret;
			this.SetAuthKey(authkey);
			this.SetSiteID(siteid);
		}
		
		///<summary>Resets the MyPWAuthenticator object</summary>
		///<remarks>This resets the authenticator prior to a new authentication.
		///All data is cleared except secret, siteid, and authkey.</remarks>
		public void Reset()
		{
			//this method is used to reset the request
			this.request.Clear();
			
			// now re-add all of the semi-static info
			this.request["authkey"] = this.authkey;
			this.request["siteid"] = this.siteid;
		}
		
		///<summary>Sets the <c>authkey</c></summary>
		///<remarks></remarks>
		///<param name="authkey">The <c>authkey</c> is the authkey provided by MyPW
		///and is used to authorize your client to authenticate a token for your
		///site.</param>
		public void SetAuthKey(string authkey)
		{
			this.request["authkey"] = authkey;
			this.authkey = authkey;
		}
		
		///<summary>Sets the <c>siteid</c></summary>
		///<remarks></remarks>
		///<param name="siteid">The <c>siteid</c> identifies your site to MyPW.</param>
		public void SetSiteID(string siteid)
		{
			this.request["siteid"] = siteid;
			this.siteid = siteid;
		}
		
		///<summary>Submit the token and its value to the authenticator</summary>
		///<remarks></remarks>
		///<param name="tokenid">This is the <c>tokenid</c> the identifies a specific
		///token to MyPW.</param>
		///<param name="tokenvalue">The <c>tokenvalue</c> is the current value displayed
		///on the token's LCD</param> 
		public void SetToken(string tokenid, string tokenvalue)
		{
			this.request["tokenid"] = tokenid;
			this.request["tokenvalue"] = tokenvalue;
		}
		
		///<summary>Sets the optional <c>sitename</c></summary>
		///<remarks></remarks>
		///<param name="sitename"><c>sitename</c> is a user (developer) defined optional
		///value that will be displayed in the transaction logs.</param>
		public void SetSiteName(string sitename)
		{
			this.request["sitename"] = sitename;
		}
		
		///<summary>Sets the optional <c>userip</c> value.</summary>
		///<remarks></remarks>
		///<param name="userip">The <c>userip</c> is an optional value that you 
		///can submit, if you would like to track the user's IP on the transaction
		///logs</param>
		public void SetUserIP(string userip)
		{
			this.request["userip"] = userip;
		}
		
		///<summary>Sets an optional note to be included in the transaction log</summary>
		///<remarks></remarks>
		///<param name="note">The <c>note</c> is the content of the note.</param>
		public void SetNote(string note)
		{
			this.request["note"] = note;
		}
		
		///<summary>Sends request to MyPW and returns a result code</summary>
		///<remarks>The result code will be:
		///	<list type="bullet">
		///		<item>-99999 = MAJOR ERROR - request couldn't be sent (networking problems?)</item>
		///		<item>-99 = Site Authentication Failure (siteid/authkey)</item>
		///		<item>-2 = Token disabled</item>
		///		<item>-1 = Token not found. </item> 
		///		<item>0 = Sucess!  Authenticated!</item>
		///		<item>others = see message</item>
		///	</list>
		///</remarks>
		public string Authenticate()
		{
			// client is the actual object that sends the request
			XmlRpcRequest client = new XmlRpcRequest();

			client.MethodName = "auth.auth";	// Set the XML RPC Method
			client.Params.Clear();	// Make sure we remove all client data
			client.Params.Add(this.request); // Now add our data
			
			// try / catch -- this actuall sends the request to MyPW
			try
			{
				this.results = (Hashtable)client.Invoke("https://services.mypw.com/RPC2");
			}
			catch (XmlRpcException serverException)			{
      			Console.WriteLine("[MyPWAuth] ERROR {0}: {1}", serverException.FaultCode, serverException.FaultString);
    		}
    		catch (Exception ex)			{
      			Console.WriteLine("[MyPWAuth] ERROR: " + ex.Message + " @ " + ex.TargetSite);
    		}
			
			// try / catch -- return the result code as a string.
			try
			{
				return (Convert.ToString(this.results["code"]));
			}
			catch (Exception ex)
			{
				Console.WriteLine("[MyPWAuth] ERROR: Response parse failure.  No valid response. @ " + ex.TargetSite);
				return ("-99999");
			}
		}
		
		///<summary>Returns the <c>message</c> from the <c>Authtenticate</c> call to MyPW</summary>
		///<remarks>If you need to display the text returned in the <c>message</c> field,
		///then this method will return it for your application to use.</remarks>
		public string GetResponseMessage()
		{
			try 
			{
				return Convert.ToString(results["message"]);
			}
			catch (Exception ex)
			{
				Console.WriteLine("[MyPWAuth] ERROR: Response parse failure. No valid response. @ " + ex.TargetSite);
				return ("Uknown error.  Unable to parse response from MyPW.  No valid reponse.");
			}
		}
		
		///<summary>This method validates the response from MyPW</summary>
		///<remarks>MyPW will sign each reply with a hash comprised of
		///several values. This method computes the hash and then compares
		///it to the one returned.  If they match, the metod returns a 
		///<c>bool true</c> to your application.  Otherwise it retuns 
		///<c>false</c>.  <i>Note - You must have passed your shared <c>secret</c>
		///to the constructor, otherwise it will always fail validation.</i></remarks>
		public bool Validate()
		{
			// Create an ASCII Encoding Object so we can covert to ASCII Byte[]
			ASCIIEncoding AE = new ASCIIEncoding();
	    	byte[] hashValue;
	    	byte[] plainValue;
	    	string plainText;
	    	
	    	// Now let's combine all of the pieces into plain test string
	    	plainText = this.secret + request["tokenid"] + request["tokenvalue"] + request["authkey"];
	    	
	    	// The crypto bits require us to convert to a byte[]
	    	// We also need to make sure its in ASCII encoding, otherwise
	    	// it will not match the result from MyPW.
	    	plainValue = AE.GetBytes(plainText);
	    		
	    	// Next create a SHA512 Hash
	    	SHA512Managed hasher = new SHA512Managed();
	  		hashValue = hasher.ComputeHash(plainValue);
	  			
	  		// Convert back to a string with Base64
	    	string hashCalced = Convert.ToBase64String(hashValue);
	    	
	    	// Compare for validation
	    	// we need try/catch because accessing results[] if there 
	    	// is a network failure will cause an exception
	    	try 
	    	{
	    		bool hashMatches = hashCalced.Equals((string)this.results["validate"]);
				return hashMatches;
			}
			catch(Exception ex)
			{
				Console.WriteLine("[MyPWAuth] ERROR: " + ex.Message + " @ " + ex.TargetSite);
				return false;
			}
		}
			
		// DisplayResults should only be used for debugging
		public void DisplayResults()
		{
			try
			{
				Console.WriteLine("==========================");
				Console.WriteLine("Code: " + results["code"]);
				Console.WriteLine("Message: " + results["message"]);
				Console.WriteLine("Server Validate: " + results["validate"]);
			}
			catch (Exception ex)
			{
				Console.WriteLine("[MyPWAuth] ERROR: " + ex.Message + " @ " + ex.TargetSite);
			}
		}
	}
}