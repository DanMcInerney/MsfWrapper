# -*- coding: utf-8 -*-

from asyncio import sleep
from .helpers import get_output_errors


class Console:

    def __init__(self, client):
        self.client = client
        self.c_id = self.get_console_id()

    def get_console_id(self):
        """
        Grabs the first available console ID.
        This method is not async because we need to run it at class instantiation.
        Additionally, you can't use the Console object until this is done so it's
        already a blocking task. This is the only function that raises an error on
        failure due to its necessity of completion.

        Returns:
            utf8 str of the console ID
        """
        con_data = self.client.call('console.list')

        if b'error_message' in con_data:
            err = con_data[b'error_message']
            raise ValueError(err)
        else:
            for c in con_data[b'consoles']:
                return c[b'id'].decode('utf8')

    async def create_console(self):
        """Creates a console and returns the console ID"""
        con_data = self.client.call('console.create')
        return con_data[b'id'].decode('utf8')

    async def destroy_console(self, c_id):
        """Destroy a console and return either success or error message"""
        con_data = self.client.call('console.destroy', [c_id])

        if b'error_message' in con_data:
            return con_data[b'error_message']
        else:
            return con_data[b'result'].decode('utf8')

    async def is_console_busy(self):
        """Check if a console is busy"""
        cons = self.client.call('console.list')[b'consoles']

        for c in cons:
            if c[b'id'].decode('utf8') == self.c_id:
                return c[b'busy']

    async def get_console_output(self, sleep_secs=1):
        """Waits for a console to not be busy then returns output, prompt, and errors via its console ID"""
        output = ''

        # Get any initial output
        output += self.client.call('console.read', [self.c_id])[b'data'].decode('utf8')

        # Make sure the console is not busy
        while not await self.is_console_busy():
            output += self.client.call('console.read', [self.c_id])[b'data'].decode('utf8')
            await sleep(sleep_secs)  # asyncio sleep

        # Get remaining output
        last_check = self.client.call('console.read', [self.c_id])
        output += last_check[b'data'].decode('utf8')
        prompt = last_check[b'prompt'].decode('utf8')

        con_data = {'output': output, 'prompt': prompt}

        return con_data

    async def run_console_cmd(self, cmd):
        """
        Runs a console cmd and gets the output

        Returns:
            con_data = {'output': 'utf8 str', 'prompt': 'utf8 str'}
        """
        cmd = cmd + '\n'

        # Success: {b'wrote': <num_of_chars>}
        self.client.call('console.write', [self.c_id, cmd])

        con_data = await self.get_console_output(self.c_id)
        output = con_data['output']
        prompt = con_data['prompt']

        err = await get_output_errors(output, cmd)

        if err:
            raise ValueError(err)

        return con_data
