# -*- coding: utf-8 -*-


class Module:

    def __init__(self, mod_path):
        self.mod_path = mod_path
        self.mod_name = mod_path.split('/')[-1]

    async def get_module_info(self, client):
        """
        API call to get the module's data. This module is one of the few that will not
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

    async def get_mod_targets(self, mod_data):
        """Gather all the potential targets for a module

        Returns:
            dict of target options"""