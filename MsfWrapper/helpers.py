# -*- coding: utf-8 -*-

async def get_output_errors(output, cmd):
    """
    List of errors that MSF may send back indicating failure of the command.
    This is purely a list made of trial and error. There's got to be a more
    canonical way of doing this but you can't just flag on "[-]" as that shows
    up even in successful exploits like EternalBlue or long-running PS cmds
    """

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
        # while another is running. It will continuously show up if we are
        # running a long-running PSH cmd
        if '2148734468' not in err:
            err = {'cmd': cmd, 'err': output}

    return err

async def convert_dict_to_sorted_list(dict):
    """Converts a dictionary object into a sorted-by-key list of tuples"""
    lst = list(dict.items())
    lst.sort()
    return lst
