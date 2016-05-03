# -*- coding: UTF-8 -*-
"""
Enjoy printing
github: https://github.com/Aploium/ColorfulPyPrint
Author: aploium@aploium.com
License: GPLv3
"""
from __future__ import print_function

from ._Beep import beep
from ._ColorfulPrint import Fore
from ._logtime import logtime
from .extra_output_destination import clean_extra_output_destination, add_extra_output_destination, \
    ExternalPrintBuffer as _ExternalPrintBuffer, extra_print_dests

__author__ = 'Aploium'
__version__ = '0.3.2'
__all__ = ['infoprint', 'dbgprint', 'warnprint', 'errprint', 'importantprint', 'ColorfulPyPrint_set_verbose_level',
           'ColorfulPyPrint_current_verbose_level', 'clean_extra_output_destination', 'add_extra_output_destination']

PRINT_TYPE_INFO = 0
PRINT_TYPE_DEBUG = 1
PRINT_TYPE_WARN = 2
PRINT_TYPE_ERROR = 3
PRINT_TYPE_IMPORTANT_NOTICE = 4

TIME_LEVEL_NONE = 0
TIME_LEVEL_TIME = 1
TIME_LEVEL_FULL = 2

O_TIME_LEVEL = TIME_LEVEL_TIME
O_VERBOSE_LEVEL = 1


def _printr(output, other_inputs, print_type=PRINT_TYPE_INFO, timelevel=O_TIME_LEVEL, is_beep=False, important_level=0):
    """
    an private function to do print function

    :param output: any
    :param other_inputs: list
    :param print_type: int
    :param timelevel: int
    :param is_beep: bool
    """
    # filter extra output destinations meet the limit
    suitable_extra_dest = [x['dest'] for x in extra_print_dests if x['important_level'] <= important_level]

    # assembly timelevel string
    if timelevel == TIME_LEVEL_NONE:
        section_time = ''
    elif timelevel == TIME_LEVEL_FULL:
        section_time = '[' + logtime(is_print_date=True) + '] '
    else:
        section_time = '[' + logtime(is_print_date=False) + '] '

    # Type&Color Section
    if print_type == PRINT_TYPE_INFO:
        section_color = Fore.GREEN
        section_type = '[INFO] '
    elif print_type == PRINT_TYPE_DEBUG:
        section_color = Fore.LIGHTBLUE_EX
        section_type = '[DEBUG] '
    elif print_type == PRINT_TYPE_WARN:
        section_color = Fore.YELLOW
        section_type = '[WARNING] '
    elif print_type == PRINT_TYPE_ERROR:
        section_color = Fore.RED
        section_type = '[ERROR] '
    elif print_type == PRINT_TYPE_IMPORTANT_NOTICE:
        section_color = Fore.LIGHTMAGENTA_EX
        section_type = '[IMPORTANT] '
    else:
        section_color = ''
        section_type = ''

    # Finally Print
    print_str = section_color + section_time + section_type
    if suitable_extra_dest:
        buffer = _ExternalPrintBuffer()
        buffer.replace_stdout()
    print_str += str(output)
    if other_inputs:
        for item in other_inputs:
            print_str += ' ' + str(item)
    print_str += Fore.RESET
    try:
        print(print_str)
    except Exception as e:
        if suitable_extra_dest:
            buffer.reset()
        print(Fore.RED + 'PRINT ERROR: ', e, Fore.RESET)
    finally:
        if suitable_extra_dest:
            buffer.reset()
    if is_beep:
        try:
            beep()
        except:
            pass

    # Print to extra destination(s)
    for item in suitable_extra_dest:
        item.write(section_time + section_type + buffer.buff)


def ColorfulPyPrint_set_verbose_level(verbose_level=1):
    """
    set output verbose level
    :type verbose_level: int
    """
    global O_VERBOSE_LEVEL
    O_VERBOSE_LEVEL = verbose_level
    return O_VERBOSE_LEVEL


def ColorfulPyPrint_current_verbose_level():
    """
    show current verbose level
    :rtype: int
    """
    global O_VERBOSE_LEVEL
    return O_VERBOSE_LEVEL


def infoprint(output, *other_inputs, **kwargs):
    para = {'v': 1,  # verbose
            'timelevel': O_TIME_LEVEL,
            'is_beep': False,
            'i': 1,  # important level (effect extra prints)
            }
    para.update(kwargs)
    if para['v'] <= O_VERBOSE_LEVEL:
        _printr(output, other_inputs, print_type=PRINT_TYPE_INFO,
                timelevel=para['timelevel'], is_beep=para['is_beep'], important_level=para['i'])


def dbgprint(output, *other_inputs, **kwargs):
    para = {'v': 3,  # verbose
            'timelevel': O_TIME_LEVEL,
            'is_beep': False,
            'i': 0,  # important level (effect extra prints)
            }
    para.update(kwargs)
    if para['v'] <= O_VERBOSE_LEVEL:
        _printr(output, other_inputs, print_type=PRINT_TYPE_DEBUG,
                timelevel=para['timelevel'], is_beep=para['is_beep'], important_level=para['i'])


def warnprint(output, *other_inputs, **kwargs):
    para = {'v': 2,  # verbose
            'timelevel': O_TIME_LEVEL,
            'is_beep': False,
            'i': 1,  # important level (effect extra prints)
            }
    para.update(kwargs)
    if para['v'] <= O_VERBOSE_LEVEL:
        _printr(output, other_inputs, print_type=PRINT_TYPE_WARN,
                timelevel=para['timelevel'], is_beep=para['is_beep'], important_level=para['i'])


def errprint(output, *other_inputs, **kwargs):
    para = {'v': 0,  # verbose
            'timelevel': O_TIME_LEVEL,
            'is_beep': False,
            'i': 2,  # important level (effect extra prints)
            }
    para.update(kwargs)
    if para['v'] <= O_VERBOSE_LEVEL:
        _printr(output, other_inputs, print_type=PRINT_TYPE_ERROR,
                timelevel=para['timelevel'], is_beep=para['is_beep'], important_level=para['i'])


def importantprint(output, *other_inputs, **kwargs):
    para = {'v': 0,  # verbose
            'timelevel': O_TIME_LEVEL,
            'is_beep': False,
            'i': 3,  # important level (effect extra prints)
            }
    para.update(kwargs)
    if para['v'] <= O_VERBOSE_LEVEL:
        _printr(output, other_inputs, print_type=PRINT_TYPE_IMPORTANT_NOTICE,
                timelevel=para['timelevel'], is_beep=para['is_beep'], important_level=para['i'])
