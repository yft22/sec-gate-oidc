This plugin used pcsc-lite and depends on
 * pcsc-lite
 * pcsc-acsccid

Need to blacklist default NFC kernel module
    cp nfc-blacklist.conf /etc/modprobe.d
    rmmod nfc and dependencies

Run pcsc manager in debug/foreground mode
  sudo /usr/sbin/pcscd -f