This is only a test.  Proper validation and sanitation of user's input needs to be done, HTTPS should be used, etc.

<h2>WHY?</h2>

Humans are incapable of creating a random password that they can remember.  Even less if you consider creating MULTIPLE random passwords that they can remember.  They always create patterns that hackers can easily exploit (Ref.: https://www.youtube.com/watch?v=zUM7i8fsf0g).  Therefore, no user-defined password will ever be strong enough and no strong computer-defined password will ever be easy to remember.

This is an attempt to create a website login process that has a relaxed password policy while providing an increased database security.

<h2>OBJECTIVES</h2>

- All user login passwords saved on the database are randomly generated and with 256-bit entropy;
	
- The only copy of the password is given to the user in an encrypted fashion, known as the code.  It can be decrypted with 2 keys:  A user's password (easy) and a unique, random, 256-bit key kept in the database;
	
- To log in, the user must provide his or her password and the code;
	
- A unique URI can be used to log in with the code incorporated in it (in the query).  This gives a login process similar to the ones used today (i.e. user must provide only his or her username & password).
	
	This gives the possibility to give to the user a 'one-click', redirecting to the user's personal login page, html document that the user can keep on his or her hardware or in the cloud, such as this one:
			
			<!DOCTYPE html>
			<html>
				<head>
					<title>Redirect</title>
				</head>
				<body>
					<script>
						window.location = 'https://localhost/login.php?code=QPUTMNwE6W4irYnODXXdaXYIxWaSvykG5QGJobEE1lhP8CRSBsygtPQM%2FB%2Fvj7iKMHXLjkJLEJToPERRqUI%2BARW3QxemF6kdn1C0KirwwcYugrkBilcAZeCBz803yBTf3yeo5ei%2B1wj7agEkSijo2A%3D%3D';
					</script>
					<noscript style='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);'>
						<a href='https://localhost/login.php?code=QPUTMNwE6W4irYnODXXdaXYIxWaSvykG5QGJobEE1lhP8CRSBsygtPQM%2FB%2Fvj7iKMHXLjkJLEJToPERRqUI%2BARW3QxemF6kdn1C0KirwwcYugrkBilcAZeCBz803yBTf3yeo5ei%2B1wj7agEkSijo2A%3D%3D'>Go to my login page</a>
					</noscript>
				</body>
			</html>
	
<h2>ADVANTAGES</h2>

- Secure one-way hashed passwords stored in the database are impossible to guess (random 256-bit);
	
- Secure one-way hashed passwords stored in the database are not the user's passwords, so if database would be compromised, user's passwords wouldn't;
	
- 'True' password stored on user's computer is encrypted with a key impossible to guess (random 256(+)-bit);
	
- User don't need a particularly difficult password to remember;
	
- User can use the same password on different websites;
	
- 'True' password can be reset while keeping the same user's password;
	
- Knowing user's password is not enough; Knowing code is not enough; Both are needed;
	
- Can be impossible to get code using key logger software when user clicks on a link to personal login page (unique URI).
	
<h2>HOW IT WORKS</h2>
	
The database contains a secure one-way hashed password and a 256-bit cryptographically secure pseudo-random key for each user (unknown to the user).

The 'true' password is also a 256-bit cryptographically secure pseudo-random number (unknown to the user).

The 'true' password is stored in a encrypted code for which the key is a combination of the database-kept key and a password given by the user (i.e. min. entropy = 256 bits).

The user is the only one who has the encrypted code, which he or she (or anyone else) can't open on his own.

The user has to present the code and his or her password.  The corresponding key is retrieved from the database, combined with the user's password and used to get the 'true' password.  The 'true' password is compared with the secure one-way hashed password in the database.

To ease the process (code has 152 characters), the user can log in with a link with the code in the query.  Therefore, two extra steps have to be taken to get maximum security:

1. To make sure the browser doesn't add the URI to the history, the request is redirected without the query.  All major browsers add only the redirected URI in the history (i.e. without the code).  Assuming a browser wouldn't adopt such behavior, the security wouldn't be compromised if one knew the personal 'login' URI, as the user's password is still needed and the log in process would be as secure as any conventional method used today.

2. The method used to write the access log of the server may have to be modified such that it doesn't record the 'code' given in the query.  For Apache servers, you need access to the httpd.conf file and do a modification similar to the one below.

  The "%r" parameter (request) includes the query.  It should be replaced by something like "%m %U %H" which includes all the information (method, URL path, protocol) of "%r", except the query:

  	  # Original LogFormat
	  LogFormat "%h %l %u %t \"%r\" %>s %b" common
	  # Comment out original CustomLog to be replaced
	  #CustomLog "logs/access.log" common
	
      # Add the following to prevent logging of sensitive data
      # Identify requests with a 'code' in the query
	  <If "%{QUERY_STRING} =~ /(^|([^&]+&)+)code=.*$/">
		  SetEnv hidequery
	  </If>
      # Set format for hidden queries
      LogFormat "%h %l %u %t \"%m %U?[hidden query] %H\" %>s %b" noquery
      # Set log for normal requests
      CustomLog "logs/access.log" common env=!hidequery
	  # Set log for requests with query that needs to be hidden
      CustomLog "logs/access.log" noquery env=hidequery

  If such step is not taken (it might be impossible on shared servers), the security wouldn't be compromised if one knew the personal 'login' URI, as the user's password is still needed and the database security would be similar to any conventional method used today.  Actually, the security level is still slightly higher since - if the database AND the server's access log are compromised - the hacker still have to find which code goes with which user, then try to guess the user's password. If there's is no match, it is impossible to know if it is because you have the wrong user's password or the wrong code.  Also, it is unlikely that all user's codes will be in the access log.

  To counter this possible threat (query stored on server access log), a counter or date can be stored in the database and the user could be forced to change the code regularly (while keeping the same password).  If needed, at a small cost for user experience, maximum security can be achieved if the code is changed at each use.

<h2>Programmer</h2>

Denny O'Breham
obreham@gmail.com
