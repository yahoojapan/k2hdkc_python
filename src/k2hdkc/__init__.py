# -*- coding: utf-8 -*-
#
# K2hdkc Python Driver under MIT License
#
# Copyright (c) 2022 Yahoo Japan Corporation
#
# For the full copyright and license information, please view
# the license file that was distributed with this source code.
#
# AUTHOR:   Hirotaka Wakabayashi
# CREATE:   Tue Feb 08 2022
# REVISION:
#

"""
k2hdkc package
"""
from __future__ import absolute_import

__all__ = ["K2hdkc"]

import ctypes
import logging
import sys
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_bool,
    c_char_p,
    c_int,
    c_short,
    c_size_t,
    c_ubyte,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_ulong,
    c_ulonglong,
    cast,
    pointer,
)
from ctypes.util import find_library
from enum import Enum
from logging import StreamHandler
from logging.handlers import TimedRotatingFileHandler
from typing import (
    Dict,
    List,  # noqa: pylint: disable=unused-import
    Optional,
    Set,
    Tuple,
    Union,
)

LOG = logging.getLogger(__name__)

# Library handles
_HANDLE: Dict[str, str] = {}


# https://docs.python.org/3/library/ctypes.html#incomplete-types
class FILE(Structure):  # noqa: pylint:disable=too-few-public-methods
    """C FILE structure"""


# https://docs.python.org/3/library/ctypes.html#incomplete-types
class time_t(Structure):  # noqa: pylint:disable=too-few-public-methods,invalid-name
    """C time_t structure"""


# KeyPack structure
# See: https://github.com/yahoojapan/k2hdkc/blob/master/lib/k2hdkc.h#L75
#
# typedef struct k2h_key_pack{
# 	unsigned char*	pkey;
# 	size_t			length;
# }K2HKEYPCK, *PK2HKEYPCK;
#
class KeyPack(Structure):  # noqa: pylint:disable=too-few-public-methods
    """C KeyPack structure"""

    _fields_ = [("pkey", POINTER(c_ubyte)), ("length", c_size_t)]


# AttrPack structure
# See: https://github.com/yahoojapan/k2hdkc/blob/master/lib/k2hdkc.h#L81
#
# typedef struct k2h_attr_pack{
# 	unsigned char*	pkey;
# 	size_t			keylength;
# 	unsigned char*	pval;
# 	size_t			vallength;
# }K2HATTRPCK, *PK2HATTRPCK;
#
class AttrPack(Structure):  # noqa: pylint:disable=too-few-public-methods
    """C Attr structure"""

    _fields_ = [
        ("pkey", POINTER(c_ubyte)),
        ("keylength", c_size_t),
        ("pval", POINTER(c_ubyte)),
        ("vallength", c_size_t),
    ]


class TimeUnit(Enum):
    """k2hdkc time units"""

    DAYS = 1
    HOURS = 2
    MILLISECONDS = 3
    MINUTES = 4
    SECONDS = 5


class LayerLogLevel(Enum):
    """k2hdkc layer log level"""

    # Silent disables logging.
    SILENT = 1
    # logs on errors
    COMMUCATION = 2
    # logs on (errors || warnings)
    K2HDKC = 3
    # logs on (errors || warnings || info)
    CHMPX = 4
    # logs on (errors || warnings || info || debug)
    K2HASH = 5


class DataType(Enum):
    """DataType for CAS API"""

    U_BYTE = 1
    U_SHORT = 2
    U_INT32 = 4
    U_LONGLONG = 8


# Initializes library handles and stores the result in the _HANDLE cache
def _init_library_handle():
    global _HANDLE  # noqa: pylint: disable=global-statement
    if _HANDLE:
        return _HANDLE

    # Loads libc and libk2hdkc and ...
    result = {}
    result["c"] = _load_libc()
    result["k2hash"] = _load_libk2hash()
    result["chmpx"] = _load_libchmpx()
    result["k2hdkc"] = _load_libk2hdkc()
    _HANDLE = result

    # 0. sets the common loglevel as logging.WARNING
    LOG.setLevel(logging.WARNING)
    formatter = logging.Formatter(
        "%(asctime)-15s %(levelname)s %(name)s:%(lineno)d %(message)s"
    )  # hardcoding
    stream_handler = StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    LOG.addHandler(stream_handler)

    # 1. sets the each layered log level.
    # 1.1. comlog
    if _HANDLE["k2hdkc"]:
        _HANDLE["k2hdkc"].k2hdkc_disable_comlog()
    # 1.1. k2hdkc
    if _HANDLE["k2hdkc"]:
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_warning()
    # 1.2. chmpx
    if _HANDLE["chmpx"]:
        _HANDLE["chmpx"].chmpx_set_debug_level_warning()
    # 1.3. k2hash
    if _HANDLE["k2hash"]:
        _HANDLE["k2hash"].k2h_set_debug_level_warning()

    return result


def _load_libc():
    ret = ctypes.cdll.LoadLibrary(find_library("c"))
    if ret is None:
        raise FileNotFoundError
    return ret


def _load_libk2hash():
    ret = ctypes.cdll.LoadLibrary(find_library("k2hash"))
    if ret is None:
        return None
    return ret


def _load_libchmpx():
    ret = ctypes.cdll.LoadLibrary(find_library("chmpx"))
    if ret is None:
        return None
    return ret


def _load_libk2hdkc():  # noqa: pylint: disable=too-many-statements
    ret = ctypes.cdll.LoadLibrary(find_library("k2hdkc"))
    if ret is None:
        return None

    # k2hdkc api
    # add_subkey API
    ret.k2hdkc_pm_set_str_subkey_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_char_p,
        c_bool,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_set_str_subkey_wa.restype = c_bool

    # cas_get API
    ret.k2hdkc_pm_cas8_str_get_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_uint8),
    ]
    ret.k2hdkc_pm_cas8_str_get_wa.restype = c_bool
    ret.k2hdkc_pm_cas16_str_get_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_uint16),
    ]
    ret.k2hdkc_pm_cas16_str_get_wa.restype = c_bool
    ret.k2hdkc_pm_cas32_str_get_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_uint32),
    ]
    ret.k2hdkc_pm_cas32_str_get_wa.restype = c_bool
    ret.k2hdkc_pm_cas64_str_get_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_uint64),
    ]
    ret.k2hdkc_pm_cas64_str_get_wa.restype = c_bool

    # cas_decrement API
    ret.k2hdkc_pm_cas_str_decrement_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas_str_decrement_wa.restype = c_bool

    # cas_increment API
    ret.k2hdkc_pm_cas_str_increment_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas_str_increment_wa.restype = c_bool

    # cas_init API
    ret.k2hdkc_pm_cas8_str_init_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint8,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas8_str_init_wa.restype = c_bool
    ret.k2hdkc_pm_cas16_str_init_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint16,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas16_str_init_wa.restype = c_bool
    ret.k2hdkc_pm_cas32_str_init_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint32,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas32_str_init_wa.restype = c_bool
    ret.k2hdkc_pm_cas64_str_init_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint64,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas64_str_init_wa.restype = c_bool

    # cas_set API
    ret.k2hdkc_pm_cas8_str_set_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint8,
        c_uint8,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas8_str_set_wa.restype = c_bool
    ret.k2hdkc_pm_cas16_str_set_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint16,
        c_uint16,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas16_str_set_wa.restype = c_bool
    ret.k2hdkc_pm_cas32_str_set_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint32,
        c_uint32,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas32_str_set_wa.restype = c_bool
    ret.k2hdkc_pm_cas64_str_set_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_uint64,
        c_uint64,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_cas64_str_set_wa.restype = c_bool

    # clear_subkeys API
    # bool k2hdkc_pm_clear_str_subkeys(k2hdkc_chmpx_h handle, const char* pkey)
    ret.k2hdkc_pm_clear_str_subkeys.argtypes = [c_uint64, c_char_p]
    ret.k2hdkc_pm_clear_str_subkeys.restype = c_bool

    # get_attributes API
    ret.k2hdkc_pm_get_str_direct_attrs.argtypes = [c_uint64, c_char_p, POINTER(c_int)]
    ret.k2hdkc_pm_get_str_direct_attrs.restype = POINTER(AttrPack)

    # get_subkeys API
    # int k2hdkc_pm_get_str_subkeys(k2hdkc_chmpx_h handle, const char* pkey, char*** ppskeyarray)
    # char** k2hdkc_pm_get_str_direct_subkeys(k2hdkc_chmpx_h handle, const char* pkey)
    ret.k2hdkc_pm_get_direct_subkeys.argtypes = [
        c_uint64,
        c_char_p,
        c_size_t,
        POINTER(c_int),
    ]
    ret.k2hdkc_pm_get_direct_subkeys.restype = POINTER(KeyPack)

    # queue_get API
    ret.k2hdkc_pm_q_str_push_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_bool,
        c_bool,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_q_str_push_wa.restype = c_bool

    # queue_put API
    ret.k2hdkc_pm_q_str_pop_wp.argtypes = [
        c_uint64,
        c_char_p,
        c_bool,
        c_char_p,
        POINTER(c_char_p),
    ]
    ret.k2hdkc_pm_q_str_pop_wp.restype = c_bool

    # keyqueue_get API
    ret.k2hdkc_pm_keyq_str_pop_wp.argtypes = [
        c_uint64,
        c_char_p,
        c_bool,
        c_char_p,
        POINTER(c_char_p),
        POINTER(c_char_p),
    ]
    ret.k2hdkc_pm_keyq_str_pop_wp.restype = c_bool

    # keyqueue_put API
    ret.k2hdkc_pm_keyq_str_push_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_char_p,
        c_bool,
        c_bool,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_keyq_str_push_wa.restype = c_bool

    # remove API
    # bool k2hdkc_pm_remove_str(k2hdkc_chmpx_h handle, const char* pkey)
    ret.k2hdkc_pm_remove_str.argtypes = [c_uint64, c_char_p]
    ret.k2hdkc_pm_remove_str.restype = c_bool

    # remove_subkeys API  # NOTE subkeys accept multiple subkeys
    ret.k2hdkc_pm_remove_str_subkey.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_bool,
    ]
    ret.k2hdkc_pm_remove_str_subkey.restype = c_bool

    # rename API
    ret.k2hdkc_pm_rename_with_parent_str_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_char_p,
        c_bool,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_rename_with_parent_str_wa.restype = c_bool

    # set_all API
    ret.k2hdkc_pm_set_str_all_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_char_p),
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_set_str_all_wa.restype = c_bool
    ret.k2hdkc_pm_set_all_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        POINTER(KeyPack),
        c_int,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_set_all_wa.restype = c_bool

    # set_subkeys API
    ret.k2hdkc_pm_set_str_subkeys.argtypes = [c_uint64, c_char_p, POINTER(c_char_p)]
    ret.k2hdkc_pm_set_str_subkeys.restype = c_bool
    #
    # k2hdkc_pm_set_subkeys
    ret.k2hdkc_pm_set_subkeys.argtypes = [
        c_uint64,
        POINTER(c_ubyte),
        c_size_t,
        POINTER(KeyPack),
        c_int,
    ]
    ret.k2hdkc_pm_set_subkeys.restype = c_bool

    # get API
    # bool k2hdkc_pm_get_str_value_wp(k2hdkc_chmpx_h handle,
    # const char* pkey, const char* encpass, char** ppval);
    ret.k2hdkc_pm_get_str_value_wp.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        POINTER(c_char_p),
    ]
    ret.k2hdkc_pm_get_str_value_wp.restype = c_bool

    # set API
    ret.k2hdkc_pm_set_str_value_wa.argtypes = [
        c_uint64,
        c_char_p,
        c_char_p,
        c_bool,
        c_char_p,
        POINTER(c_ulong),
    ]
    ret.k2hdkc_pm_set_str_value_wa.restype = c_bool

    # open API
    # k2hdkc_chmpx_h k2hdkc_open_chmpx_full(const char* config,
    # short ctlport, const char* cuk, bool is_auto_rejoin, bool no_giveup_rejoin,
    # bool is_clean_bup)
    ret.k2hdkc_open_chmpx_full.argtypes = [
        c_char_p,
        c_short,
        c_char_p,
        c_bool,
        c_bool,
        c_bool,
    ]
    ret.k2hdkc_open_chmpx_full.restype = c_uint64
    ret.k2hdkc_open_chmpx_ex.argtypes = [c_char_p, c_short, c_bool, c_bool, c_bool]
    ret.k2hdkc_open_chmpx_ex.restype = c_uint64
    ret.k2hdkc_open_chmpx.argtypes = [c_char_p]
    ret.k2hdkc_open_chmpx.restype = c_uint64

    # close API
    # bool k2hdkc_close_chmpx_ex(k2hdkc_chmpx_h handle, bool is_clean_bup)
    ret.k2hdkc_close_chmpx_ex.argtypes = [c_uint64, c_bool]
    ret.k2hdkc_close_chmpx_ex.restype = c_bool
    return ret


# Initializes library handlers
_init_library_handle()


# Gets library handler
def get_library_handle():
    """Gets C library handles"""
    return _init_library_handle()


# Configures the loglevel.
def set_log_level(log_level):
    """Sets the log level"""
    LOG.setLevel(log_level)


# TODO  noqa: pylint: disable=fixme
# support function to set a logfile as package level function


# Configures the layer loglevel.
def set_layer_log_level(log_level):
    """Sets the layer log level"""
    if not isinstance(log_level, LayerLogLevel):
        raise TypeError("log_level shoube a LayerLogLevel object")
    # 1. gets the current loglevel
    # current_log_level = logging.getLevelName(LOG.level)

    global _HANDLE  # noqa: pylint: disable=global-statement, global-variable-not-assigned
    if not _HANDLE:
        raise RuntimeError("library handle should be defined")

    # 2. sets the each layer loglevel
    if LOG.level == logging.NOTSET:
        # 1. set network layer silent
        _HANDLE["k2hdkc"].k2hdkc_disable_comlog()
        # 2. set k2hdkc layer silent
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_silent()
        # 3. set chmpx layer silent
        _HANDLE["chmpx"].chmpx_set_debug_level_silent()
        # 4. set k2hash layer silent
        _HANDLE["k2hash"].k2h_set_debug_level_silent()
    elif LOG.level == logging.DEBUG:
        # 1. set network layer silent
        _HANDLE["k2hdkc"].k2hdkc_enable_comlog()
        # 2. set k2hdkc layer silent
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_dump()
        # 3. set chmpx layer silent
        _HANDLE["chmpx"].chmpx_set_debug_level_dump()
        # 4. set k2hash layer silent
        _HANDLE["k2hash"].k2h_set_debug_level_dump()
    elif LOG.level == logging.INFO:
        # 1. set network layer silent
        _HANDLE["k2hdkc"].k2hdkc_disable_comlog()
        # 2. set k2hdkc layer silent
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_message()
        # 3. set chmpx layer silent
        _HANDLE["chmpx"].chmpx_set_debug_level_message()
        # 4. set k2hash layer silent
        _HANDLE["k2hash"].k2h_set_debug_level_message()
    elif LOG.level == logging.WARNING:
        # 1. set network layer silent
        _HANDLE["k2hdkc"].k2hdkc_disable_comlog()
        # 2. set k2hdkc layer silent
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_warning()
        # 3. set chmpx layer silent
        _HANDLE["chmpx"].chmpx_set_debug_level_warning()
        # 4. set k2hash layer silent
        _HANDLE["k2hash"].k2h_set_debug_level_warning()
    elif LOG.level == logging.ERROR:
        # 1. set network layer silent
        _HANDLE["k2hdkc"].k2hdkc_disable_comlog()
        # 2. set k2hdkc layer silent
        _HANDLE["k2hdkc"].k2hdkc_set_debug_level_error()
        # 3. set chmpx layer silent
        _HANDLE["chmpx"].chmpx_set_debug_level_error()
        # 4. set k2hash layer silent
        _HANDLE["k2hash"].k2h_set_debug_level_error()
    else:
        # level unknown
        raise ValueError(
            "unknown logging level:{}".format(logging.getLevelName(LOG.level))
        )

    return True


#
# import k2hdkc modules
#
from k2hdkc.k2hdkc import K2hdkc  # noqa: pylint:disable=wrong-import-position

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
