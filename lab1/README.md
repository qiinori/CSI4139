# Password encyption and decryption

Part I
File protecting/unprotecting program

For this part of the lab, we decided to use Java for our code. A lot of libraries about cryptography already exists in Java and we used multiple of them for our code. We only use one program that would both act as the sender and encode the message and also act as the receiver and decode it when received. We used RSA for both the symmetric and asymmetric encryption.

We start our program by creating the different keys that are going to be used. One symmetric key that we assume is only available to the sender, and 2 pairs of public and private keys for signing and encrypting the key. The public key used for  encryption and the private key used for signing are “given” to the sender while the private key used in decryption and the public key for verifying are “given” to the receiver. Only the sender has access to the symmetric key used for encrypting the message.

Symmetric Encryption and Decryption

In symmetric encryption, both the sender and the receiver need to use the same private key for encryption and decryption. The private key should be kept secret for both parties. We used AES-256 bits for our code because it is a pretty secure algorithm for Symmetric encryption. Thus, we apply AES-256 to Symmetric cryptography.

    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
 
    public static SecretKey createAESKey() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }


Asymmetric Encryption and Decryption

So like said before, in asymmetric cryptography different from symmetric, we generate a pair of keys, one is a private key and the other is a public key. We also used RSA-256 bits for our key generation for its security and strength. The goal is that the public key can be given to anyone, trusted or not, but by having the private key kept secret the information is still safe because only having the public key is not enough. We use this asymmetric encryption for the sender to tell the symmetric key used to the receiver. By encrypting that key using asymmetric encryption, only the receiver can get access to the symmetric key (other than the sender who is the original person with the key) and then decrypt the message.

Another operation that uses a pair of public and private keys is called signature and verifying. During asymmetric cryptography process, the plain text(message) is hashed along with the sender’s private key,the digital signature for the sender is created. Then the receiver should hash the message and verify the signature with the sender's public key, this provides an added level of authentication. If the digital signature is verified, then the message’s authenticity and data integrity is ensured.
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }
 
    public static boolean verifyPassord(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

Hash:
	For our hashing algorithm we used BCrypt. BCrypt is a strong algorithm that is still to this day resistant to brute-force search attacks even with increasing computational power.
 private static final String RSA = "RSA";
 
    public static KeyPair generateRSAKeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

	
Part II
Vulnerabilities and Countermeasures 

For this laboratory, our team was using three web scanning software. They are: Vega, OWASP Zap, PowerFuzzer. All of these programs are open sources and can be accessed without any additional payments. All of them perform automated scans of the targeted URL and identify their vulnerabilities.
A website that was chosen as a target for was our capstone course page (https://course.ncct.uottawa.ca). The web page was scanned on all possible bugs and vulnerabilities. We have listed screenshots of our work results below. 
“X-Frame-Options”  is a vulnerability where a header that is not included in the HTTP response to protect against 'ClickJacking' attacks. This header is usually used to indicate whether or not a browser should be allowed to render the page in <frame, <iframe>, <embed> or <object>. A possible solution could be to ensure the header is set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).
“ Secure Pages Include Mixed Content”,is a vulnerability where content accessed via HTTP instead of HTTPS. A possible solution for this could be to take a page that is available over SSL/TLS and comprises it completely of content which is transmitted over SSL/TLS. The page must not contain any content that is transmitted over unencrypted HTTP. This includes content from third party sites.
“Private IP Disclosure” is a vulnerability where a private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, IP-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems. A possible solution could be to remove the private IP address from the HTTP response body.  For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.
“Absence of Anti-CSRF Tokens” is a vulnerability where no Anti-CSRF tokens were found in an HTML submission form. A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a website has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf. A possible solution could be to use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
“Cookie Without SameSite Attribute” is a vulnerability where a cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective countermeasure to cross-site request forgery, cross-site script inclusion, and timing attacks. A possible solution could be to ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.
“Timestamp Disclosure” is a vulnerability where a timestamp was disclosed by the application/web server - Unix. A possible solution could be to manually confirm that the timestamp data is not sensitive and that the data cannot be aggregated to disclose exploitable patterns.
“ Information Disclosure - Suspicious Comments”is a vulnerability where the response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments. A possible solution could be to remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

“ Incomplete or No Cache-control and Pragma HTTP Header Set”  is a vulnerability where the cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content. A possible solution could be to ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.










“X-Frame-Options”  is a vulnerability where a header that is not included in the HTTP response to protect against 'ClickJacking' attacks. This header is usually used to indicate whether or not a browser should be allowed to render the page in <frame, <iframe>, <embed> or <object>. A possible solution could be to ensure the header is set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).
“ Secure Pages Include Mixed Content”,is a vulnerability where content accessed via HTTP instead of HTTPS. A possible solution for this could be to take a page that is available over SSL/TLS and comprises it completely of content which is transmitted over SSL/TLS. The page must not contain any content that is transmitted over unencrypted HTTP. This includes content from third party sites.
“Private IP Disclosure” is a vulnerability where a private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, IP-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems. A possible solution could be to remove the private IP address from the HTTP response body.  For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.
“Absence of Anti-CSRF Tokens” is a vulnerability where no Anti-CSRF tokens were found in an HTML submission form. A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a website has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf. A possible solution could be to use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
“Cookie Without SameSite Attribute” is a vulnerability where a cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective countermeasure to cross-site request forgery, cross-site script inclusion, and timing attacks. A possible solution could be to ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.
“Timestamp Disclosure” is a vulnerability where a timestamp was disclosed by the application/web server - Unix. A possible solution could be to manually confirm that the timestamp data is not sensitive and that the data cannot be aggregated to disclose exploitable patterns.
“ Information Disclosure - Suspicious Comments”is a vulnerability where the response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments. A possible solution could be to remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

“ Incomplete or No Cache-control and Pragma HTTP Header Set”  is a vulnerability where the cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content. A possible solution could be to ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.
 “Cookie No HttpOnly Flag” is a vulnerability where A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible. A possible solution could be to ensure that the HttpOnly flag is set for all cookies.
“Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)” is a vulnerability where the web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to. A possible solution could be to ensure that your web server, application server, load balancer are configured to suppress "X-Powered-By" headers.
“ X-Content-Type-Options Header Missing” is a vulnerability where the Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing. A possible solution could be to ensure that the application/web server sets the Content-Type header appropriately and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
In conclusion, our test was able to find any critical weaknesses on this web page. Moreover, “X-Frame-Options Header Scanner” is the only vulnerability that could put the entire system in danger of attack. We believe if the theoretical client would use our solution, this system’s security could be significantly improved.
