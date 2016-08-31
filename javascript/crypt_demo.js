var pw = "This is a very strong password";
var pt = "This is some example plaintext";

var encrypted = CryptoJS.AES.encrypt(pt, pw);
encrypted.toString(); // U2FsdGVkX1+0m/gle/XQX1shjnpveUrl1fO3oOlurPMlTks6+oQlEPfOrucihzEz
encrypted.salt.toString(); // b49bf8257bf5d05f
encrypted.ciphertext.toString(); // 5b218e7a6f794ae5d5f3b7a0e96eacf3254e4b3afa842510f7ceaee722873133
console.log("encrypted:", encrypted.toString());

var encrypted_str = "U2FsdGVkX1/NgSAYoVBC/+I4tmVZshgs9dxIXvAJcydAWVWl2xlSLj7eLtgBGPpB";
// var decrypted = CryptoJS.AES.decrypt(encrypted.toString(), pw);
var decrypted = CryptoJS.AES.decrypt(encrypted_str, pw);
console.log("decrypted:", decrypted.toString(CryptoJS.enc.Utf8));

