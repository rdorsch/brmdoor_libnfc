# Brmdoor via libnfc and libfreefare

This is a fork of the excellent
https://github.com/hiviah/brmdoor_libnfc.git . The for reduces the
code to the nfc and authentification related functions. I.e. integration
functions used in the Brmlab in Prague are removed. As a side effect
there are no dependencies left to code not in Debian buster (upcoming
Debian 10).

In particular I removed

- wiringPi support on the Raspberry Pi (used for pysically unlocking
the door and an *OPEN/CLOSE state* button for people to indicate if
place is opened to public.
- IRC support to report information to an irc channel
- SFTP/SpaceAPI support to upload status information to a server

This removes all dependencies to software not included in Debian
buster


This is an access-control system implementation via contactless ISO 14443A cards
and a PN53x-based reader. So you basically swipe your card, and if it's in
database, the door unlocks.

Info about authorized users and their cards and keys is stored in sqlite database.

This was originally designed for Raspberry (Raspbian), but it also runs on other distros on Rapi and
x86 if you have the PN532 USB reader.

The main daemon is implemented in `brmdoor_nfc_daemon.py`.

Exmple one place where it's used - https://brmlab.cz/project/brmdoor/start

The brmlab page also show electrical components and connection (Raspi and lock use different voltages). Any lock can be 
used with `brmdoor_libnfc` as long as you can trigger it via GPIO. More secure locks (BERA-E/BERA-D with automatic lock
and panic trigger) or a cheap electromagnetic lock.

## Supported cards and authentication methods

* by UID of ISO-14443 card (Mifare Classic, Desfire, Ultralight...) - not safe since it's cloneable, but it's commonly used in comme
* Yubikey Neo HMAC-SHA1 - most safe option, uncloneable
* Mifare Desfire - Ed25519 signature of UID (currently no known clones available; although some features could be cloned,
  it's not enough for anyone to create such partial clones)

Test code is also provided to get payment signature (cryptogram) from Visa and Mastercard, but it's not used.

## Building and dependencies

You need just to run `make`. Additional dependencies:

- [libnfc](https://github.com/nfc-tools/libnfc/releases), in Debian and Ubuntu as libnfc-dev
- [libfreefare](https://github.com/nfc-tools/libfreefare), in Debian and Ubuntu install libfreefare-bin and libfreefare-dev
- [python-axolotl-curve25519](https://github.com/tgalal/python-axolotl-curve25519), in Ubuntu and Debian install python-axolotl-curve25519
- [SWIG version 2](http://www.swig.org/) - to generate Python-C++ bindings, SWIG 3 is known to cause segfaults sometimes
- [WiringPi2 pythonic binding](https://github.com/WiringPi/WiringPi2-Python) (for switching lock on Raspberry)
- [python-irc](https://pypi.python.org/pypi/irc) >= 16.0, use "pip install irc", the one in repos is old
- [pysftp](https://pypi.org/project/pysftp/) - for uploading SpaceAPI-formatted status to some host
  - optional runtime dependency, not needed unless you set SFTP SpaceAPI upload to true

All dependencies can be installed on Ubuntu or Debian/Raspbian via:

    apt install libnfc-dev libfreefare-bin libfreefare-dev python-axolotl-curve25519 swig2.0 python-dev

To build, just run make:

    make

## Howto

1. Create the database

        python create_authenticator_db.py authenthicator_db.sqlite

2. Copy sample config file, edit your pins, DB file location, timeouts

        cp brmdoor_nfc.config.sample brmdoor_nfc.config

3. Add some users

  - either authentication by UID, e.g.:

        ./brmdoor_adduser.py -c brmdoor_nfc.config -a uid 34795FCC SomeUserName

  - authentication by Yubikey's HMAC-SHA1 programmed on slot 2

        ./brmdoor_adduser.py -c brmdoor_nfc.config -a hmac 40795FCCAB0701 SomeUserName 000102030405060708090a0b0c0d0e0f31323334

  - to program Yubikey slot 2 to use HMAC with given key (requires package `yubikey-personalization`), use:

        ykpersonalize -2 -ochal-resp -ohmac-sha1 -ohmac-lt64 -oserial-api-visible
        
  - authentication using signed UID as NDEF message on Desfire:

  -- Add user to sqlite database using UID of Defire card
  
        ./brmdoor_adduser.py -c brmdoor_nfc.config -a ndef 04631982cc2280 SomeUserName
  
  -- you need to generate Ed25519 keypair, store the private key somewhere safe (to programm more Desfire cards later) and put the public in config file brmdoor_nfc.config
  
        ./generate_ed25519_keypair.py
        
  -- you need to put the Desfire card on the reader and program the Desfire card to have the signature
       
        ./write_signed_ndef_on_desfire.py private_key_in_hex
        
Finally, run the daemon:

        sudo python brmdoor_nfc_daemon.py brmdoor_nfc.config

## Configuring libnfc devices

If you have PN532 device on other bus than USB (e.g. SPI), first search for it using:

    sudo nfc-scan-device -i

After that, create file `/etc/nfc/libnfc.conf` with line describing your device
from `nfc-scan-device` above, e.g. for SPI device:

    device.connstring = "pn532_spi:/dev/spidev0.0"

This daemon expects the library to be already configured to find the PN532 device.

If you installed libnfc from source, the default directory might be
`/usr/local/etc/nfc` instead of `/etc/nfc`.

## Conflicts with other running software - pcscd, pn533 kernel modules

If you have `pcscd` running, it will take over the reader and you can't use it. Kill/stop pcscd service/process if running.

Similarly, you have to blacklist `pn533` and `pn533_usb` kernel modules (usually in a file like `/etc/modprobe.d/blacklist.conf`).

## Photo of an actual installation

![Raspberry with stepup](https://brmlab.cz/_media/project/brmdoor/brmlab_03.jpg?cache=&w=900&h=600&tok=bcf9ca)

![Connection to PN532 reader](https://brmlab.cz/_media/project/brmdoor/brmlab_04.jpg?cache=&w=900&h=600&tok=575eb2)

Security note: it's better to have reader behind door, but this door is metal (thus external or wormhole antenna needed). 
Even though the reader is not connected directly to *open* PIN which could be triggered by applying power to it.

There are two ways to do it:

- Separate antenna connected to [external antenna PINs provided by Adafruit PN532 board](https://learn.adafruit.com/adafruit-pn532-rfid-nfc/downloads)
  Antenna is quite difficult to tune (requires right LC circuit with proper coils and capacitors).
- [Wormhole antenna](https://i.imgur.com/fclA2b2.jpg) - two coils connected with wire. It generally works, but is not
  very reliable.

## Startup with systemd and GNU screen

Example of startup unit for systemd, put in `/etc/systemd/system/brmdoor.service` and this repo cloned in `/root/brmdoor_libnfc`:

    [Unit]
    Description=brmdoor
     
    [Service]
    Type=forking
    User=root
    ExecStart=/usr/bin/screen -L -d -m -S brmdoor
    WorkingDirectory= /root/brmdoor_libnfc/
     
    [Install]
    WantedBy=multi-user.target


After adding the service file, run `systemctl daemon-reload` to notify systemd that unit was added. 
To enable automatic startup, use `systemctl enable brmdoor.service`.

A `/root/.screenrc` file that will run the daemon in detached screen:

    autodetach on
    startup_message off 

    screen -t brmdoor 0 /root/brmdoor_libnfc/brmdoor_start.sh


## Security considerations

Using SFTP for upload of status should be used with "internal-sftp" setting. This chroots the upload user's directory,
doesn't allow script or code execution. You need to chown the directory to root and make it not writable by non-root
users (requirement for internal-sftp). E.g. make `brmdoor-web` (used for sftp upload) user part of `sftp` group and have
  
    Subsystem sftp internal-sftp

    Match Group sftp
       ChrootDirectory %h
       ForceCommand internal-sftp
       AllowTcpForwarding no

For SFTP upload to work, target host needs to already to be in `~/.ssh/known_hosts` when making connection, otherwise
you'll get an exception. Simply connect via command-line sftp before running, check and accept the fingeprint beforehand.

Also, as noted before, reader should be behind door (mostly for vandalism). But the reader is not connected directly to 
*open* PIN, so it's not possible to simply apply voltage to it in this design even if you expose the reader.
PIN to open door should be in no case accessible from outside the door (like having Raspi on the outside).

## Known bugs (TODO)

* IRC disconnect is sometimes detected late, e.g. when trying to send message that door was open. This
  causes the message to be lost, but the reconnect will kick in
* Freenode loses packets (RST) seeming silent connection to be still alive when they are not.
* Periodic PING could theoretically solve this, but when I tried I got kicked out, so also you need to find the right
  interval
  
## Notes

You could use Android Host Card Emulation to emulate a Desfire - it actually just expects one application, D2760000850101.

See an [example of HCE NDEF emulation](https://github.com/TechBooster/C85-Android-4.4-Sample/blob/master/chapter08/NdefCard/src/com/example/ndefcard/NdefHostApduService.java).

You could just modify `write_signed_ndef_on_desfire.py` to write out the JSON into a file and then put the 
generated NDEF file into application so it will respond with it when

## Testing

If you don't want to test it on Raspberry directly, it's possible to run on x86 with USB-based PN532, e.g. 
[ACR 122U](https://www.acs.com.hk/en/products/3/acr122u-usb-nfc-reader/) or
[ACR 122T](https://www.acs.com.hk/en/products/109/acr122t-usb-tokens-nfc-reader/).

Open/close switch can be simulated by ordinary file, for unlocker you can use do-nothing `unlocker.Unlocker` class.
Note that there are subtle differences in PN532 handling which we also discovered only by experience, notably that SPI
version cannot do interrupts while the USB version can. This has the effect that it causes 100% CPU use on SPI version,
because it actively polls, while it works on USB version without 100% CPU usage. This issue has been fixed in the past
so that the SPI version doesn't consume 100% CPU by just waiting for card.

