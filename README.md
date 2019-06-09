## OnLineADFSAuthenticator

It is a **Java** class which takes care of authenticating to a **Microsoft SharePoint Online** with **Active Directory Federation Services** based authentication mechanism:

Being "sharePointAddress", "userMailAddress" and "userPassword" the string representations of the SharePoint site url ("https://example.sharepoint.com/sites/..."), 

the user domain email address and his/her password, two public methods (**obtainAuthenticationCookie** and **obtainFormDigestValue**) return respectively the **HTTP Cookie** 

and **Form Digest** strings, which are needed to subsequent interactions with the SharePoint via the **REST API** (see Example Usage below).

An internal class named "OnlineADFSException" aggregates the different exceptions which may arose and gets thrown itself for further possible handlings.

## Example Usage

```
import com.rocco.vincenzo.java.sharepoint.OnLineADFSAuthenticator;

OnLineADFSAuthenticator authenticator = new OnLineADFSAuthenticator();
try{           
	String cookie = authenticator.obtainAuthenticationCookie(sharePointAddress, userMailAddress, userPassword);
	String digest = authenticator.obtainAuthenticationCookie(cookie, sharePointAddress);   
} catch (OnLineADFSAuthenticator.OnlineADFSException e){
            System.out.print(e.toString());
  } 
```

## Motivation

After having found different approaches scattered over several articles on the internet (also based on other languages), I decided to consolidate what finally worked for me:

it was mainly about figuring out the exact format of the two .xml files in the resources folder which are used to create the server payload.


## License

[GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0-standalone.html)