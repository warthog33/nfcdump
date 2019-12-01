# nfcdump
Utility for decoding dump files from Android NFC logs

It is designed to be used for decoding or decryption the output from the state logs

$adb shell dumpsys nfc | ./nfcdump

The above command will read the dump from the attached Android device and dump the contents of the log, decrypting if necessary.

Requires development packages
- OpenSSL ( on Ubuntu installed with sudo apt-get install libssl-dev)
- zlib (on Ubuntu installed with sudo apt-get install zlib1g-dev) 
