package com.rocco.vincenzo.java.sharepoint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author Vincenzo Rocco
 */

/**
* Class which takes care of authenticating to Microsoft SharePoint Online with Active Directory Federation Services
* based authentication mechanism.
*
* @author      Vincenzo Rocco
*/
public class OnLineADFSAuthenticator {
    
    private static final String MICROSOFTREALMQUERYSITE = "https://login.microsoftonline.com/getuserrealm.srf";
    private static final String MICROSOFTSTSSITE = "https://login.microsoftonline.com/extSTS.srf";
    private static final String FEDERATION = "urn:federation:MicrosoftOnline";
    private static final String SETCOOKIE = "Set-Cookie";
    private static final String AUTHENTICATIONCOOKIENAME = "SPOIDCRL";
    private static final String LOGINEQ= "login=";
    private static final String XMLEQ= "&xml=1";
    private static final String AUTHORIZATION = "Authorization";
    private static final String IDCRLPATH = "/_vti_bin/idcrl.svc/";
    private static final String IDCRLSTARTHEADER = "BPOSIDCRL";
    private static final String XIDCRLACC = "X-IDCRL_ACCEPTED";
    private static final String XIDCRLVALUE = "t";
    private static final String APICONTEXT = "/_api/contextinfo";
    private static final String STSAUTHURLTAG = "RealmInfo/STSAuthURL";
    private static final String ADFSTOTAG = "Envelope/Header/To";
    private static final String ADFSMESSAGEIDTAG = "Envelope/Header/MessageID";
    private static final String ADFSUSERNAMETAG = "Envelope/Header/Security/UsernameToken/Username";
    private static final String ADFSPASSWORDTAG = "Envelope/Header/Security/UsernameToken/Password";
    private static final String ADFSCREATEDTAG = "Envelope/Header/Security/Timestamp/Created";
    private static final String ADFSEXPIRESTAG = "Envelope/Header/Security/Timestamp/Expires";
    private static final String ADFSADDRESSTAG = "Envelope/Body/RequestSecurityToken/AppliesTo/EndpointReference/Address";
    private static final String ADFSREPLYSAMLASSERTIONTAG = "Envelope/Body/RequestSecurityTokenResponse/RequestedSecurityToken";
    private static final String STSSECURITYTAG = "Envelope/Header/Security";
    private static final String STSADDRESSTAG = "Envelope/Body/RequestSecurityToken/AppliesTo/EndpointReference/Address";
    private static final String STSREPLYBINARYTOKENTAG = "Envelope/Body/RequestSecurityTokenResponse/RequestedSecurityToken/BinarySecurityToken";
    private static final String SHAREPOINTDIGESTTAG = "GetContextWebInformation/FormDigestValue";
    
    /**
    * Returns the authentication <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/net/HttpCookie.html">HttpCookie</a> to be used with SharePoint. 
    * The address argument must specify the root ("default.aspx") of the SharePoint page
    * to interact with. 
    * <p>
    * This method can throw a SharepointOnlineADFSException exception, 
    * a wrapper to all the single exception (IOException, ParserConfigurationException,
    * SAXException etc) that the method internally used can raise. 
    *
    * @param  address  The HTTP address  of the SharePoint to authenticate to
    * @param  mail The authenticating user's email address
    * @param  password  The authenticating user's domain password
    * @return      <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/net/HttpCookie.html">HttpCookie</a> 
    * @throws      OnlineADFSException    If any of the internal methods raises an exception
    * @author      Vincenzo Rocco
    */
    public String obtainAuthenticationCookie(String address, String mail, String password) throws OnlineADFSException{
        
        
        // Get Federation Authorization Server for User
        
        String domain = null;
        String endpoint = null;
        try{
           URL url = new URL(address);
           domain = url.getHost();
           endpoint = url.getProtocol() + "://" + domain;  
        } catch(MalformedURLException mue){
          throw new OnlineADFSException(" Invalid URL: Incorrect protocol used? "); 
        }             
        List<String[]> connectionProperties = new ArrayList<>();
        connectionProperties.add( new String[]{"Content-Type", "application/soap+xml; charset=utf-8"});      
        String[] tagsForRealmNames = {STSAUTHURLTAG};
        String federationAuthServer;
        try{
            federationAuthServer = (String) queryServerForReply(MICROSOFTREALMQUERYSITE, null, "POST", null, tagsForRealmNames, mail, true, false); 
        }catch (NullPointerException npe){
            throw new OnlineADFSException(" Unable to retrieve Federation Authorization Server for user, correct mail address used? ");
        }
        

        // Get SAML Node from Federation Authorization Server
        
        Instant timeCreated = Instant.now();
        Instant timeExpired = Instant.now().plusSeconds(600);
        String created  = DateTimeFormatter.ISO_INSTANT.format(timeCreated);
        String expires  = DateTimeFormatter.ISO_INSTANT.format(timeExpired);
        String messageID = java.util.UUID.randomUUID().toString();       
        String[] tagsfForADFSTemplate = {ADFSTOTAG, ADFSMESSAGEIDTAG, ADFSUSERNAMETAG, ADFSPASSWORDTAG, ADFSCREATEDTAG, ADFSEXPIRESTAG, ADFSADDRESSTAG};
        String[] valuesForADFSTemplate = {federationAuthServer, messageID, mail, password, created, expires, FEDERATION};       
        String filledInADFSTemplate = (String) xmlParserHelper("TemplateToADFS.xml", null, tagsfForADFSTemplate, valuesForADFSTemplate, false, false, null);
        String[] tagsForSAMLAssertionNames = {ADFSREPLYSAMLASSERTIONTAG}; 
        Node samlNode;
        try{
          samlNode  = (Node) queryServerForReply(federationAuthServer, filledInADFSTemplate, "POST", connectionProperties, tagsForSAMLAssertionNames, null, true, true );
        }catch (NullPointerException npe){
            throw new OnlineADFSException(" No binary security token received from Microsoft Online Login (STS) server, correct sharepoint address used? ");
        }finally {
            filledInADFSTemplate = null;
            valuesForADFSTemplate = null;
            mail = null;
            password = null;
        }
        
        
        // Get Binary Security Token from Microsoft Online Login Server
        
        String[] tagsfForSTSTemplate = {STSSECURITYTAG, STSADDRESSTAG};
        String[] valuesfForSTSTemplate = {"null", endpoint};
        String filledSTSTemplate = (String) xmlParserHelper("TemplateToSTS.xml", null, tagsfForSTSTemplate, valuesfForSTSTemplate, false, true, samlNode);
        String[] tagsForBinaryTokenNames = {STSREPLYBINARYTOKENTAG};           
        String binarySecurityToken;
        try{
            binarySecurityToken = (String) queryServerForReply(MICROSOFTSTSSITE, filledSTSTemplate, "POST", connectionProperties, tagsForBinaryTokenNames, null, true, false); 
        }catch (NullPointerException npe){
            throw new OnlineADFSException(" No binary security token received from Microsoft Online Login (STS) server, correct sharepoint address used? ");
        }finally {
            filledSTSTemplate = null;
            samlNode = null;
        }
        
        
        // Get Cookie from Sharepoint Site
        
        connectionProperties.clear();
        String idcrlServerAddress = new StringBuilder(endpoint).append(IDCRLPATH).toString();
        String idcrlHeadValue = new StringBuilder(IDCRLSTARTHEADER).append(" ").append(binarySecurityToken).toString();        
        connectionProperties.add( new String[]{AUTHORIZATION, idcrlHeadValue});
        connectionProperties.add( new String[]{XIDCRLACC, XIDCRLVALUE});  
        String cookieString;
        try{
            cookieString = (String) queryServerForReply(idcrlServerAddress, null, "GET", connectionProperties, null, null, false, false); 
        }catch (NullPointerException npe){
            throw new OnlineADFSException(" No cookie received from sharepoint server, correct sharepoint address used? ");
        }
        return cookieString; 
    }
    
    /**
    * Returns the Digest to be used together with the HttpCookie in each query to SharePoint. 
    * The address argument must specify the root ("default.aspx") of the SharePoint page
    * to interact with. 
    * <p>
    * This method can throw a SharepointOnlineADFSException exception, 
    * a wrapper to all the single exception (IOException, ParserConfigurationException,
    * SAXException etc) that the method internally used can raise. 
    *
    * @param  cookie   The HttpCookie returned by {@link #obtainAuthenticationCookie(String, String, String) obtainAuthenticationCookie} method
    * @param  address  The HTTP address  of the SharePoint to authenticate to
    * @return      Digest in String format
    * @throws      OnlineADFSException    If any of the internal methods raises an exception
    * @author      Vincenzo Rocco
    */
    public String obtainFormDigestValue(String cookie, String address) throws OnlineADFSException{
    
        
        // Get FormDigest from Sharepoint 
        
        String domain = null;
        String endpoint = null;
        try{
           URL url = new URL(address);
           domain = url.getHost();
           endpoint = url.getProtocol() + "://" + domain;  
        } catch(MalformedURLException mue){
            throw new OnlineADFSException(" Invalid URL: Incorrect protocol used? "); 
        }
        String contextServerAddress = new StringBuilder(endpoint).append(APICONTEXT).toString();
        List<String[]> connectionProperties = new ArrayList<>();
        connectionProperties.add(new String[]{"Cookie", cookie});
        connectionProperties.add(new String[]{"X-ClientService-ClientTag", "SDK-JAVA"});        
        String[] tagsForDigest = {SHAREPOINTDIGESTTAG};       
        return (String) queryServerForReply(contextServerAddress, null, "POST", connectionProperties, tagsForDigest, null, true, false);
    }
    
    private Object queryServerForReply(String serverAddress, String template, String method, List<String[]> properties, String[] tags, String mailAddress, boolean xmlParserNeeded, boolean isNodeNeeded) throws OnlineADFSException{
        Object replySection = null;
        String body;    
        if(mailAddress != null){
            body = new StringBuilder(LOGINEQ).append(mailAddress).append(XMLEQ).toString();
        }else{
            body = template;
        }        
        String reply = httpConnectionHelper(serverAddress, method, properties, body);        
        if(reply != null){
            if(xmlParserNeeded){
                if(isNodeNeeded){
                    replySection = xmlParserHelper(null, reply, tags, null, true, true, null);
                }else{
                    replySection = xmlParserHelper(null, reply, tags, null, true, false, null);
                }
            }else{
                replySection = reply;
            }           
        }
        return replySection;
    }
    
    private String httpConnectionHelper(String addressServer, String method, List<String[]> properties, String body) throws OnlineADFSException{
        String returnedString = null;
        try{
        URL urlMS = new URL(addressServer);
        URLConnection connection = urlMS.openConnection();
        HttpURLConnection httpConnection = (HttpURLConnection) connection;      
        httpConnection.setAllowUserInteraction(false);
        httpConnection.setConnectTimeout(15000);
        httpConnection.setRequestMethod(method);
        if(properties != null && properties.size() > 0){
            properties.forEach((s) -> {
                httpConnection.addRequestProperty(s[0], s[1]);
            }); 
        }          
        if(method.equals("POST")){
            httpConnection.setDoInput(true);
            httpConnection.setDoOutput(true);    
            if(body == null){
                StringBuilder propertyStringForBody = new StringBuilder();
                for(String[] connectionProperty : properties){
                    propertyStringForBody.append(URLEncoder.encode(connectionProperty[0], "UTF-8"));
                    propertyStringForBody.append("=");
                    propertyStringForBody.append(URLEncoder.encode(connectionProperty[1], "UTF-8"));
                    propertyStringForBody.append("&");           
                }
                body = propertyStringForBody.substring(0, propertyStringForBody.length()-1);
            }
            byte[] postDataBytes = new byte[body.length()];
            postDataBytes = body.getBytes("UTF-8");
            httpConnection.getOutputStream().write(postDataBytes);           
            Reader in = new BufferedReader(new InputStreamReader(httpConnection.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int c; (c = in.read()) >= 0;){
                sb.append((char) c);
            }
            returnedString = sb.toString();
        }else{
            Map<String, List<String>> mapForHeaders;
            mapForHeaders = httpConnection.getHeaderFields();
            List<String> cookiesHeaderString = mapForHeaders.get(SETCOOKIE);
            for (String cookieString : cookiesHeaderString){
                if(cookieString.contains(AUTHENTICATIONCOOKIENAME)){
                returnedString = cookieString;
                }
            }
        }
        httpConnection.disconnect();
        } catch (IOException ioex){
            if(ioex.getMessage().contains("HTTP response code: 500")){
                throw new OnlineADFSException(" Internal Server Error: Incorrect mail address or password supplied ");             
            }else{
                throw new OnlineADFSException(ioex.getMessage());
            }
        }
        return returnedString;
    }
    
    private Object xmlParserHelper(String templateFileName, String xmlAsString, String[] tagsPathNames, String[] valuesForTags, Boolean isReadNeeded, boolean isNodeNeeded, Node node) throws OnlineADFSException{       
        Object returnedObject = null;
        try{
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document d;
        if(templateFileName != null){
            ClassLoader cl = ClassLoader.getSystemClassLoader();
            d = db.parse(cl.getResourceAsStream(templateFileName));
        }else{
            InputSource is = new InputSource(new StringReader(xmlAsString));
            d = db.parse(is);
        }
        XPath xpath = XPathFactory.newInstance().newXPath();      
        if(isReadNeeded){
            Node nodeToReadFrom = (Node) xpath.compile(tagsPathNames[0]).evaluate(d, XPathConstants.NODE); 
            if(isNodeNeeded){
                returnedObject = nodeToReadFrom.getFirstChild();
            } else{   
                returnedObject = nodeToReadFrom.getTextContent();               
            }            
        }else{
            int k = 0;
            if(isNodeNeeded){
                Node samlImported = d.importNode(node, true);
                Node nodeToWriteTo = (Node) xpath.compile(tagsPathNames[0]).evaluate(d, XPathConstants.NODE);
                nodeToWriteTo.appendChild(samlImported); 
                k++;
            }
            for(int i=k; i<tagsPathNames.length; i++){
                Node nodeToWriteTo = (Node) xpath.compile(tagsPathNames[i]).evaluate(d, XPathConstants.NODE);
                nodeToWriteTo.setTextContent(valuesForTags[i]); 
            }
            DOMSource domS = new DOMSource(d);
            StringWriter sw = new StringWriter();
            StreamResult sr = new StreamResult(sw);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer t = tf.newTransformer();
            t.transform(domS, sr);
            returnedObject = sw.toString();
            }   
        }catch (IOException |ParserConfigurationException | SAXException | XPathExpressionException | TransformerException psxt){
            throw new OnlineADFSException(" Failed creating xml payload from " + templateFileName + " ");
        }
        return returnedObject;
    }
    
    /**
    * Wrapper class to all exceptions (IOException, ParserConfigurationException,
    * SAXException, etc) that can be raised by the internal methods 
    * of SharepointOnlineADFSException.  
    *
    * @author      Vincenzo Rocco
    */
    public class OnlineADFSException extends Exception{
        
        public OnlineADFSException(){
            super();
        }
        
        public OnlineADFSException(String message){
            super(message);
        }
    }  
}