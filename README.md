# Knot

A secured communication application using the technique of E2EE (End-To-End Encryption).

## What's so special?

Ever wondered why the existing communication application doesn't stops you from sending a attachment/file that might be harmful?
-NO!!? Then give it a go, you will get to know that if you can send a malicious file to the other, then the same can happen with you. Now ask yourself is it still safe using the applications?

Still don't get it?
- Let us assume one example:
  Entity A and B both are good friends and they are even connected with each other through a communication application, sharing messages and attachments with each other. Say, the entity A sent a malicious file "harmless.exe" with a harmless wrapper to B, now the moment B downloads it through the application then the malicious file gets triggered silenty compromising the B's device. This whole concept is what we know "Post-Decryption Problem".

But, we have solution now!
-We present you Knot, an E2EE application for communication, this application is responsible identifying the nature of the file and then taking appropriate action.
-Wait! do you think we are stopping you from sending a file that might be for fun? No, Know doesn't stops you from sending anything (It is obvious that I won't wish an application to prevent me from sending a simple programming file to my friend), but it analyses the attachments nature and other specification before you download that is all the analyses happens on the receiver's side.

Still find it like other applications?
- Maybe, this section convince you trying it.
- Knot not just analyses the file but also neutralizes it with the appropriate techniques making the received attachments/files suitable and safe to open and allows you to access the content securely.
- But, how do we know the file sent to me was malicious so that I can avoid downloading the files/attahcment being sent by a particular person? To deal with it Knot also tells you about the level of harmful a specific file could be:

- LOW-- No or minimal risk involved.
- MEDIUM-- Can be risky to download hence the file gets neutralized properly.
- HIGH-- Highly risky to donwload the, hence the file is neutralized if possible, but if not then the user is not advised to open such file.

## Does it involve any such machine learning model for the analysis?
- Short answer is No.
