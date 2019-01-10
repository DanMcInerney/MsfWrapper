# -*- coding: utf-8 -*-

from .helpers import convert_dict_to_sorted_list

class Module:

    def __init__(self, mod_path):
        self.mod_path = mod_path
        self.mod_name = mod_path.split('/')[-1]

    async def run_module(self, client):


    async def get_mod_info(self, client):
        """API call to get the module's data. This module is one of the few that will not
        encode it's returned values to UTF8 because it's too complex.

        Returns:
            Dictionary with the following byte string keys:
                b'type'
                b'name'
                b'fullname'
                b'rank'
                b'disclosuredate'
                b'description'
                b'license'
                b'filepath'
                b'arch'
                b'platform'
                b'authors'
                b'privileged'
                b'references'
                b'targets'
                b'default_target'
                b'stance'
                b'options'
        """
        mod_data = client.call('module.info', [None, self.mod_path])

        return mod_data

    async def create_settings_cmd(self, exploit_cmd='run', **kwargs):
        """Return a string which can be run in MSF console to run a module"""
        cmd = f'use {self.mod_path}\n'

        # Set all the settings options
        for key, val in kwargs.items():
            cmd += f'set {key} {val}\n'

        # End with the exploit cmd (run, exploit -j, etc)
        cmd += exploit_cmd

        return cmd
            
    async def get_req_options(self, client):
        """Gets all the required options that don't have a default value set"""
        req_opts = []

        opts = client.call('module.options', [None, self.mod_path])

        for o in opts:
            if opts[o][b'required']:
                if b'default' not in opts[o]:
                    req_opts.append(o.decode('utf8'))

        return req_opts

    async def get_mod_target(self, mod_data, platform):
        """Gather all the potential targets for a module.

        Some examples:
        struts_dmi_exec - 0   Windows Universal
                          1   Linux Universal
                          2   Java Universal
        jboss_maindeployer - 0   Automatic (Java based)
                             1   Windows Universal
                             2   Linux Universal
                             3   Java Universal
        rpc_cmsd_opcode21 - 0   IBM AIX Version 5.1

        Args:
            mod_data (dict): nonutf8 dict of module data
            platform (utf8): value of the MSF returned session data dict, eg, 'windows', 'aix'

        Returns:
            str: the utf8 string of the target number
        """
        # Sort the module's target dictionary to make sure the target numbers are in order
        # targets = [(0, b'Automatic'), (1, b'Windows')]
        targets = await convert_dict_to_sorted_list(mod_data[b'targets'])
        platform = platform.lower()

        for t in targets:
            target_num = str(t[0])
            target_desc = t[1].decode('utf8').lower()

            if 'automatic' in target_desc:
                return target_num

            # If it doesn't autotarget then go for the universal platform target
            elif 'universal' in target_desc and platform in target_desc:
                return target_num

            # If no autotarget and no universal, just use default which is '0'
            else:
                return '0'

