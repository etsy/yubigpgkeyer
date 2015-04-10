# YubiGPGKeyer

Generating RSA keys on Yubikeys is a delight many of us have enjoyed, and it's fine for a single key. Once you start doing more than key, say an organisation's worth, it quickly gets less enjoyable.

This script can help with that, by providing a semi-reasonable command line interface to automate as much as possible of that process.

## Requirements

* Python 3.
* pinentry-hax from [pinentry-hax](https://gist.github.com/barn/e3ff508c3032da3ff905) in the same directory. Needed for setting the PIN unattended.
* [ykneomgr](https://developers.yubico.com/libykneomgr/) "brew install ykneomgr"
* [ykpers](https://yubico.github.io/yubikey-personalization/) "brew install ykpers"
* [gnupg2](https://www.gnupg.org/) version 2.0.27 only tested. "brew install gnupg2"
* Some [Yubikey Neo Nanos](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/)

## Notes

Firmware version of the Yubikey is *very* important. The versions that have worked with this are 3.3.7. Earlier have had different PIN requirements, later, well, who knows. This isn't the most reliable or rugged process.

There's a lot of unplugging and plugging back in involved.

Also running `gpg2 --card-status` can help kick it, if it can't find the card. Also waiting until the light turns off.

See also [Ben Hughes' blog on the subject](https://mumble.org.uk/blog/2015/03/17/pining-for-gpg-to-try/).

## Usage.

```
usage: gpg_gener8.py [-h] --name "Mr. Etsy" --email "mr_etsy@example.org"
                     [--json] [--overwrite] [--pin 1234] [--adminpin 12345]
                     [--newpin 4321] [--newadminpin 54321] [--randomnewpin]
                     [--randomnewadminpin] [--forcecard neo-nano]
gpg_gener8.py: error: the following arguments are required: --name/-n, --email/-e
```

## Example

Run the simple, not unwieldly at all:

```
localtoast% python3 gpg_gener8.py --name 'Isabel Tate' --email 'issy@example.org' --pin 123456 --adminpin 123456 --randomnewpin --randomnewadminpin
```

Which, after some prompting, will output:

```
For name "Isabel Tate", email: issy@example.org
Yubikey serial: 3281265
PIN set to: 793574
Admin PIN set to: 23457830
Public key:
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== cardno:000202925496
```

There's the JSON output too, if you wish to feed to it in to something else.

# Bugs

Almost certainly, see the [issue tracker](https://github.com/etsy/yubigpgkeyer/issues) on github.

# Credits

Thanks to [ecraven](https://github.com/ecraven) for pinentry-emacs.

Thanks to [@antifuchs](https://twitter.com/antifuchs) for assisting with battling pinentry and GPG.
