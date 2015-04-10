#! /usr/bin/env PYTHONPATH='' python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
# -----------------------------------------------------------
# Filename      : gpg_gener8.py
# Description   : Poorly automate some of generating SSH keys in yubikeys
# Created By    : Ben Hughes <ben@etsy.com>
# Date Created  : 2015-03-16 17:24
#
# License       : MIT
#
# Yeah, I probably should use https://github.com/Yubico/python-yubico but I
# didn't notice that existed until half way through.
#
# There's probably a python module for gpg and card support too... Whatever.
#
# Requires the yubikey tools ('ykpers' in brew) and gpg stuff ('gnupg2' and
# 'gpg-agent' in brew) to be installed. Doesn't bother checking for them.
#
# Todo:
# * detect when PINs are locked out 'PIN retry counter : 0 3 3' and act.
# * detect when PINs are wrong too.
#
# (c) Copyright 2015, Etsy all rights reserved.
# -----------------------------------------------------------
__author__ = "Ben Hughes"
__version__ = "0.1337"

import re
import os
import sys
import json
import time
import shlex
import shutil
import argparse
from subprocess import Popen, PIPE
from random import randint

# Check what version we're running on
if sys.version_info < (3, 2):
    sys.stdout.write("Sorry, requires Python >3.2, because I'm the worst.\n")
    sys.exit(1)


def random_len(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


class YubiKeyMagic(object):

    def __init__(self, DEBUG=False):
        self.keytime = '4y'  # Default to 4 years for keys.
        self.ipc_file = os.path.expanduser('~/.insecure_pretend_ipc')

        # beat out the argpase dict to attrs
        self.assign_vars(vars(self.parseargs()))

        self.get_yubikey_serial()

        # Work out if the card is already configured.
        self.card_configured()

        # work out if we've tried to set random pins...
        self.assign_pins()

        if self.newpin or self.newadminpin:
            self.changepin = True
        else:
            self.changepin = False

        print("New pin is set to %s, new admin pin is %s, changing: %s" %
              (self.newpin, self.newadminpin, self.changepin))

    def assign_pins(self):
        if self.randomnewpin:
            self.newpin = random_len(6)
        if self.randomnewadminpin:
            self.newadminpin = random_len(10)

    def assign_vars(self, a):
        """
        Hack out the dict from argparse in to a bunch of accessors for
        the class
        """
        for k in a.keys():
            setattr(self, k, a[k])

    def get_yubikey_model(self):
        """
        "Bit hack"
        look at what version of yubikey is inserted. Assumes ykinfo exists
        """

        if self.forcecard:
            self.model = self.forcecard
            return self.model

        print("Finding which type of yubikey we have.")
        model = os.popen('ykinfo -I').read().rstrip()
        if model == 'product_id: 111':
            self.model = 'neo'
        elif model == 'product_id: 116':
            self.model = 'neo-nano'
        else:
            return None

        return self.model

    def get_yubikey_serial(self):
        """
        Get the serial number, so we can find it...
        FEEL THE RUBBY!
        """
        serial = os.popen('ykinfo -s').read().rstrip()
        if 'serial: ' in serial:
            self.serial = serial.split(': ')[1]
        else:
            print('Failed to find serial.')
            sys.exit(24)

    def fix_yubikey_mode(self):
        """From the ykpersonalize man page:
              -m mode
                 2    OTP/CCID composite device.
                 6    OTP/U2F/CCID composite device.
                 Add 80 to set MODE_FLAG_EJECT, for example: 81
        """
        modes = {'neo': '82',
                 'neo-nano': '82'}

        model = self.get_yubikey_model()

        print("Checking it's in the right mode.")
        if model not in modes.keys():
            print("Yubikey doesn't do CCID. No dice.")
            sys.exit(20)

        curmode = None
        while curmode is None:
            curmode = os.popen('ykneomgr -m').read().rstrip()
            if 'No device found' in curmode:
                print("sleeping and trying again. Unplug it & replug it.")
                time.sleep(2)
                curmode = None
            elif modes[model] in curmode:
                print('Mode already set, all good.')
                return True
            else:
                print("Mode is currently: %s" % curmode)

        if self.can_overwrite():
            print("Setting mode for yubikey for doing CCID")

            ykpers_cmd = 'ykpersonalize -y -v -m{m}'.format(m=modes[model])
            if os.system(ykpers_cmd) != 0:
                print("Failed to change yubikey to do CCID")
                sys.exit(24)
        else:
            print("Not modifying written yubikey")
            print("Use --overwrite if you wish to destroy this key.")
            sys.exit(23)

    def can_overwrite(self):
        """
        return true if it's not configured, or we're okay to overwrite.
        Otherwise returns false
        """
        if not self.configured:
            return True
        else:
            return self.overwrite

    def make_cmd_string(self, commands):
        return "\n".join(commands) + "\n"

    def card_configured(self):
        """ Look for:
    Signature key ....: 7ED6 6360 7222 6AFC 61EE  26AE 11F3 2D39 9CB7 1542
    Encryption key....: 28AF C015 6AB9 0707 D9C3  C23F 5CD2 A26B 7D36 66D6
    Authentication key: 9655 FFFC C4A0 F4D3 87EB  498B 4DAF B5C4 7DCA AB87
        in the card status output

        return true/false based on whether card is configured or not.
        """

        with Popen(shlex.split('gpg2 --card-status'), stdout=PIPE) as p:
            cardstatus = p.stdout.read().decode()

        if p.returncode != 0:
            print("Failed to get card status.")
            sys.exit(10)

        has_keys = re.compile(r"""(?:Signature|Encryption|Authentication)
                                  \s+ key [\s\.]* :
                                  \s+ [0-9A-F]{4}\s .* """, re.VERBOSE)
        matches = has_keys.search(cardstatus)

        self.configured = matches is not None
        return self.configured

    def gen_that_key(self, name=None, email=None):
        """
        Open a file descriptor to some random FD, gpg2 --card-edit it.
        """
        if name is None:
            name = self.name
        if email is None:
            email = self.email

        # This is a fragile mess of blind commands to run against gpg2
        # --card-edit. Is there a nicer way to format this? Should I use expect
        # (hiss) instead?
        mess_of_blind_gpg_commands = {
            'neo': {'configured': ['admin', 'generate',
                                   'y', self.keytime,
                                   'y', name,
                                   email, '',
                                   'O', 'quit'],
                    'unconfigured': ['admin', 'generate',
                                     self.keytime, 'y',
                                     name, email,
                                     '', 'O',
                                     'quit'], },
            'neo-nano': {'configured': ['admin', 'generate',
                                        'n', 'y',
                                        self.keytime, 'y',
                                        name, email,
                                        '', 'O',
                                        'quit'],
                         'unconfigured': ['admin', 'generate',
                                          'n', self.keytime,
                                          'y', name,
                                          email, '',
                                          'O', 'quit']},
        }

        # model = self.get_yubikey_model()

        if self.configured:
            print("Using the configured version of %s" % self.model)
            cmds = mess_of_blind_gpg_commands[self.model]['configured']
        else:
            cmds = mess_of_blind_gpg_commands[self.model]['unconfigured']

        in_fd, out_fd = os.pipe()
        cmd = 'gpg2 --command-fd {fd} --card-edit'.format(fd=in_fd)

        # if not self.configured and self.model is 'neo-nano':
        self.do_a_pin(self.adminpin, self.pin)
        # else:
        # self.do_a_pin(self.pin, self.adminpin)

        self.mess_with_pinentry()

        try:
            with Popen(shlex.split(cmd), pass_fds=[in_fd]) as p:
                os.close(in_fd)  # unused in the parent

                with open(out_fd, 'w', encoding='utf-8') as command_fd:
                    command_fd.write(self.make_cmd_string(cmds))

            if p.returncode != 0:
                print("Failed to generate GPG key?")
                sys.exit(10)

        finally:
            os.unlink(self.ipc_file)
            self.unmess_with_pinentry()

    def do_a_pin(self, oldpin, newpin):
        """
        for changing pins, or actually for generating keys (where
        oldpin and newpin are actually pin and adminpin)
        """

        ipc_file = self.ipc_file

        # Yup, this is happening. A FILE BASED IPC METHOD.
        if os.path.exists(ipc_file):
            os.unlink(ipc_file)  # safety delete.

        old_umask = os.umask(0o077)  # safety umask!
        try:
            with open(ipc_file, 'w') as f:
                f.write('round=0\n')
                f.write("oldpin=%s\n" % oldpin)
                f.write("newpin=%s\n" % newpin)
        finally:
            os.umask(old_umask)

        return True

    def change_pin(self, oldpin='123456', newpin='123456', admin=False):
        """
        http://bit.ly/18Vvn7b was useful!
        https://gist.github.com/barn/425fd3c13c3f501f9d81#file-pinentry-emacs

        So change a pin from something to something else.

        Use a file with:
            # round=<0|1|2>
            # oldpass=1234
            # newpass=4321

        which is then read by the pinentry programme to change the PIN.

        No really, that's what is happening.
        """

        regular_passwd_change = ['passwd', 'quit']
        admin_passwd_change = ['admin', 'passwd', '3', 'Q', 'quit']

        # This does the pinentry side. Makes a pretend pinentry using
        # pinentry-hax. Requires calling mess_with_pinentry() to make gpg use
        # that pinentry.
        self.do_a_pin(oldpin, newpin)

        try:
            in_fd, out_fd = os.pipe()
            cmd = 'gpg2 --command-fd {fd} --card-edit'.format(fd=in_fd)

            self.mess_with_pinentry()

            with Popen(shlex.split(cmd), pass_fds=[in_fd], stdin=PIPE) as p:
                os.close(in_fd)  # unused in the parent

                with open(out_fd, 'w', encoding='utf-8') as command_fd:
                    if admin:
                        command_text = admin_passwd_change
                    else:
                        command_text = regular_passwd_change
                    command_fd.write(self.make_cmd_string(command_text))
        finally:
            os.unlink(self.ipc_file)
            self.unmess_with_pinentry()

        if p.returncode is not 0:
            print("Failed to change a password...")
            os.exit(21)

    def get_public_key(self):
        """
        So this appears to never work with the neo I have unless I
        take it out and put it back in.  I hope it is fixed on the
        neo-nanos.
        """

        print("This is awful, but I can't see there being any other way ):")
        input("Press return when you've popped the Yubikey out and back in:")
        print("")

        gpg_ssh_cmd = 'gpg-agent --daemon --enable-ssh-support ssh-add -L'
        with Popen(shlex.split(gpg_ssh_cmd),
                   stdout=PIPE,
                   close_fds=True,
                   env={'SSH_AUTH_SOCK': '',
                        'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'}
                   ) as p:
            self.pubkey = p.stdout.read().decode()
        # self.pubkey = os.popen(gpg_ssh_cmd).read()
        # print("Your public key is:\n%s" % pubkey)

    def mess_with_pinentry(self):
        """
        steps are:
            write/swap out ~/.gnupg/gpg-agent.conf:
                https://gist.github.com/barn/425fd3c13c3f501f9d81
            `echo RELOADAGENT | gpg-connect-agent`
            then run change password workflow.
            swap everything back.
            lament.
        Thanks to @antifuchs for the help!
        """

        # # Find the pinentry script included with this.
        #
        # pinentry_script = '~/codes/yubi/scripts/pinentry-hax'
        # pinentry_script = os.path.expanduser(pinentry_script)
        script_dir = os.path.dirname(os.path.realpath(__file__))
        pinentry_script = os.path.join(script_dir, 'pinentry-hax')
        if not os.path.isfile(pinentry_script):
            print("Cannot find a pinentry script at %s" % pinentry_script)
            sys.exit(27)

        gpg_agent_conf = os.path.expanduser('~/.gnupg/gpg-agent.conf')

        # shutil.move(..)
        if os.path.isfile(gpg_agent_conf):
            shutil.move(gpg_agent_conf, gpg_agent_conf + '.orig')

        with open(gpg_agent_conf, 'w') as f:
            f.write("pinentry-program {piney}".format(piney=pinentry_script))

        # I could popen, or whatever.
        os.system('echo RELOADAGENT | gpg-connect-agent')

    def unmess_with_pinentry(self):
        """
        boldly unmess the overwriting and renaming of gpg-agent.conf from
        the aforementioned mess_with_pinentry function.
        """
        gpg_agent_conf = os.path.expanduser('~/.gnupg/gpg-agent.conf')
        os.unlink(gpg_agent_conf)
        shutil.move(gpg_agent_conf + '.orig', gpg_agent_conf)

    def parseargs(self):
        """
        argparse is nicer than getopt/optparse

        This is a bit messy, but that's argument parsing for you.
        """

        parser = argparse.ArgumentParser(description='Hack me a key.')

        parser.add_argument('--name', '-n', metavar='"Mr. Etsy"',
                            required=True, help='Name to generate key for')
        parser.add_argument('--email', '-e', metavar='"mr_etsy@example.org"',
                            required=True, help='Email address for the key')

        parser.add_argument('--json', '-j', dest='json',
                            action='store_true', help='output just in JSON')

        parser.add_argument('--overwrite', '-o', dest='overwrite',
                            action='store_true', default=False,
                            help='Overwrite an existing key')

        # We can have random or fixed pins, not both.
        group_pin = parser.add_mutually_exclusive_group()
        group_adminpin = parser.add_mutually_exclusive_group()

        parser.add_argument('--pin', metavar='1234', type=int,
                            default='123456', help='current PIN')
        parser.add_argument('--adminpin', metavar='12345', type=int,
                            default='12345678', help='current admin PIN')

        group_pin.add_argument('--newpin', metavar='4321', type=int,
                               help='desired PIN')
        group_adminpin.add_argument('--newadminpin', metavar='54321', type=int,
                                    help='desired admin PIN')

        group_pin.add_argument('--randomnewpin', dest='randomnewpin',
                               action='store_true')
        group_adminpin.add_argument('--randomnewadminpin',
                                    dest='randomnewadminpin',
                                    action='store_true')

        parser.add_argument('--forcecard', '-f', metavar='neo-nano',
                            help='Override key type')
        return parser.parse_args()

    def print_results(self):
        if self.json:
            d = {'name': self.name, 'email': self.email,
                 'pin': self.newpin, 'adminpin': self.newadminpin,
                 'serial': self.serial, 'pubkey': self.pubkey}
            print(json.dumps(d))
        else:
            # Just badly format all the output with some prints
            print('For name "{name}", email: {email}'.format(name=self.name,
                                                             email=self.email))
            print('Yubikey serial: {serial}'.format(serial=self.serial))
            if self.newpin is not None:
                print('PIN set to: {pin}'.format(pin=self.newpin))
            if self.newadminpin is not None:
                print('Admin PIN set to: {pin}'.format(pin=self.newadminpin))
            print('Public key:\n{pubkey}'.format(pubkey=self.pubkey))

    def generate(self):
        self.fix_yubikey_mode()

        print("Sleeping for 5...")
        time.sleep(5)

        if self.changepin:
            print("Changing the PIN")
            self.change_pin(self.pin, self.newpin)
            print("Changing the Admin PIN")
            self.change_pin(self.adminpin, self.newadminpin, admin=True)

            # Now we've set them, assign them back.
            self.adminpin = self.newadminpin
            self.pin = self.newpin

        print("Generating key...")
        self.gen_that_key()

        self.get_public_key()
        self.print_results()


if __name__ == "__main__":
    y = YubiKeyMagic()
    y.generate()
