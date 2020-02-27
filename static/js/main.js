function enc_password(password) {
    let encrypt=new JSEncrypt();
    encrypt.setPublicKey(public_key);
    let rsa_password　=　encrypt.encrypt($('#password').val());
}