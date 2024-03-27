#!/usr/bin/env python
import sys
import argparse
import logging
import cmd2
from cmd2 import Bg,Fg,style
from cmd2 import Statement
import os
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from libs.tsch import TSCH_EXEC
CODEC = sys.stdout.encoding


class AtShell(cmd2.Cmd):
    CMD_RUN = style("Run Command", fg=Fg.WHITE, bg=Bg.LIGHT_RED, bold=True) 
    CMD_LOCAL = style("Local Command", fg=Fg.WHITE, bg=Bg.LIGHT_BLUE, bold=True)
    CMD_POST = style("Post Exploitation", fg=Fg.WHITE, bg=Bg.LIGHT_GREEN, bold=True)
    def __init__(self, username, password, domain, hashes, aesKey, k, dc_ip, session_id, address, interface,CODEC):
        super().__init__(allow_cli_args=False, include_ipy=False)
        delattr(cmd2.Cmd, 'do_macro')
        delattr(cmd2.Cmd, 'do_edit')
        delattr(cmd2.Cmd, 'do_py')
        delattr(cmd2.Cmd, 'do_run_pyscript')
        delattr(cmd2.Cmd, 'do_run_script')
        delattr(cmd2.Cmd, 'do_shortcuts')
        delattr(cmd2.Cmd, 'do_quit')
        self.self_in_py = False
        self.maxrepeats = 3
        self.prompt = 'ATShell (%s@%s)> ' % (username, address)
        self.at_op = TSCH_EXEC(username, password, domain, hashes, aesKey, k, dc_ip, session_id, CODEC)
        self.at_op.play(address, interface)
        self.intro = style('[+] Type help for list of commands.', fg=Fg.WHITE, bg=Bg.DARK_GRAY, bold=True) + ' 🚀'

    def do_set(self, args):
        """Set a configuration option"""
        args = args.split()
        if len(args) != 2:
            self.poutput("Usage: set <option> <value>")
            return
        option, value = args
        if option == "debug":
            if value.lower() == "true":
                logging.getLogger().setLevel(logging.DEBUG)
            elif value.lower() == "false":
                logging.getLogger().setLevel(logging.INFO)
            else:
                self.poutput("Invalid value. Use true or false.")
        super().do_set(" ".join(args))
    
    def complete_set(self, text, line, begidx, endidx):
        debug_choices = ['true', 'false']
        if 'debug' not in line:
            # Use basic_complete method for other options
            return self.basic_complete(text, line, begidx, endidx, self.settables)
        else:
            return [choice for choice in debug_choices if choice.startswith(text)]
          
    def do_shell(self, s):
        """Executes a local shell command"""
        os.system(s)

    def do_lcd(self, s):
        """Changes the local directory"""
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    up_parse = cmd2.Cmd2ArgumentParser()
    up_parse.add_argument('local', type=str, help='Local file to upload')
    up_parse.add_argument('remote', type=str, help='Remote file to upload')
    @cmd2.with_argparser(up_parse)
    def do_upload(self, s):
        """Uploads a file to the target"""
        local = s.local
        remote = s.remote
        self.at_op.upload_file(local, remote)

    down_parse = cmd2.Cmd2ArgumentParser()
    down_parse.add_argument('remote', type=str, help='Remote file to download')
    # set default to current directory
    down_parse.add_argument('-l','--local', type=str, help='Local file to download', default="./", required=False)
    @cmd2.with_argparser(down_parse)
    def do_download(self, s):
        """Downloads a file from the target"""
        remote = s.remote
        local = s.local
        self.at_op.download_file(remote, local)

    ps_parse = cmd2.Cmd2ArgumentParser()
    ps_parse.add_argument('command', type=str, help='Command to execute')
    @cmd2.with_argparser(ps_parse)
    def do_ps_exec(self, s):
        """Executes a powershell command on the target"""
        s = s.command
        logging.debug('Executing ps command: %s' % s)
        self.at_op.execute_powershell(s)

    cmd_parse = cmd2.Cmd2ArgumentParser()
    cmd_parse.add_argument('command', type=str, help='Command to execute')
    @cmd2.with_argparser(cmd_parse)
    def do_cmd_exec(self, s):
        """Executes a command on the target"""
        command = s.command
        logging.debug('Executing cmd command: %s' % command)
        self.at_op.execute_cmd_command(command)

    def do_execute_assembly(self, line):
        """Executes a .NET assembly on the target"""
        input = line.split(" ")
        if len(input) < 1 or len(line) == 0 :
            logging.warning("Example: execute_assembly /tmp/Rubeus.exe hash /password:X")
            return
        if len(input) == 1:
            prog = input[0]
            args = ""
        else:
            prog = input[0]
            args = " ".join(input[1:])
        logging.debug('Executing assembly: %s, args: %s' % (prog, args))
        self.at_op.execute_assembly(prog, args)

    def default(self, statement: Statement):
        self.at_op.execute_cmd_command(statement.command)


    def do_exit(self, s):
        """Terminates the server process (and this session)"""
        print('Bye!\n')
        return True

    def emptyline(self):
        return False
    
    cmd2.categorize((do_shell, do_lcd), CMD_LOCAL)
    cmd2.categorize((do_ps_exec, do_cmd_exec), CMD_RUN)
    cmd2.categorize((do_upload, do_download, do_execute_assembly), CMD_POST)
    

# Process command-line arguments.
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("-i","--interface", action="store", help="Interface to use.", default="TSCH", choices=("TSCH","ATSVC"))
    parser.add_argument('-session-id', action='store', type=int, help='an existed logon session to use (no output, no cmd.exe)')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    logging.warning("This will work ONLY on Windows >= Vista")

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    shell = AtShell(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.session_id, address, options.interface, CODEC)
    shell.cmdloop()
