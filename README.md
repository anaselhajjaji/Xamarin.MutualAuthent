# Xamarin Mutual Authentication sample
## Project content
- **Client** Console application 
- **Server** Console application
- **Xamarin.Android** that acts as Client, two modes for TLS Mutual Authentication connection establishing: Java way (that currently works perfectly) and the .Net way (same code as **Client**) that's not working for the moment.
## Certificates Generation using OpenSSL
In order to be able to install the certificate in Android as Trusted CA, we need to create a file "android_options.txt" that contains the line below:
'basicConstraints=CA:true'



## References
1. https://aboutssl.org/how-to-create-and-import-self-signed-certificate-to-android-device/
2. https://www.codeproject.com/Articles/326574/An-Introduction-to-Mutual-SSL-Authentication
