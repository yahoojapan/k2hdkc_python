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
"""K2hdkc Python Driver"""
from __future__ import absolute_import
from copy import deepcopy
import ctypes
from ctypes import pointer, byref, cast, POINTER, Structure
from ctypes import c_bool, c_ubyte, c_size_t, c_short, c_int, c_ulonglong, c_char_p
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64
import logging
import os
from pathlib import Path
from struct import pack, unpack
import sys
from k2hdkc import TimeUnit
import k2hdkc

LOG = logging.getLogger(__name__)


class K2hdkc:
    """
    K2hdkc class provides methods to handle key/value pairs in k2hdkc hash database.
    """
    K2H_INVALID_HANDLE = 0

    def _set_k2h_handle(self):
        """Sets the k2h handle"""
        # handle = self._libk2hdkc.k2hdkc_open_chmpx(
        #     c_char_p(self._conf_file.encode()))
        # handle = self._libk2hdkc.k2hdkc_open_chmpx_ex(
        #     c_char_p(self._conf_file.encode()), c_short(self._port),
        #     c_bool(self._rejoin), c_bool(self._rejoin_forever),
        #     c_bool(self._clear_backup))
        handle = self._libk2hdkc.k2hdkc_open_chmpx_full(
            c_char_p(self._conf_file.encode()), c_short(self._port),
            (c_char_p(self._cuk.encode()) if self._cuk else None),
            c_bool(self._rejoin), c_bool(self._rejoin_forever),
            c_bool(self._clear_backup))

        if handle == self.__class__.K2H_INVALID_HANDLE:
            raise RuntimeError("handle should not be K2H_INVALID_HANDLE")
        self._handle = handle

    def __init__(self,
                 conf_file,
                 port=8031,
                 cuk=None,
                 rejoin=True,
                 rejoin_forever=True,
                 clear_backup=True):
        """
        K2hdkc constructor.
        """
        self._handle = 0

        if not isinstance(conf_file, str):
            raise TypeError("conf_file should be a str object")
        if not os.path.exists(Path(conf_file)):
            raise RuntimeError("conf_file:{} should exists".format(conf_file))
        if not isinstance(port, int):
            raise TypeError("port should be a int object")
        if cuk and not isinstance(cuk, str):
            raise TypeError("cuk should be a str object")
        if not isinstance(rejoin, bool):
            raise TypeError("rejoin should be a bool object")
        if not isinstance(rejoin_forever, bool):
            raise TypeError("rejoin_forever should be a bool object")
        if not isinstance(clear_backup, bool):
            raise TypeError("clear_backup should be a bool object")

        self._conf_file = conf_file
        self._port = port
        self._cuk = cuk
        self._rejoin = rejoin
        self._rejoin_forever = rejoin_forever
        self._clear_backup = clear_backup

        try:
            # https://docs.python.org/3/library/ctypes.html#ctypes.LibraryLoader.LoadLibrary
            self._libc = k2hdkc.get_library_handle()["c"]
            if not self._libc:
                raise Exception('unable to load c library')
            self._libk2hash = k2hdkc.get_library_handle()["k2hash"]
            if not self._libk2hash:
                raise Exception('unable to load k2hash library')
            self._libchmpx = k2hdkc.get_library_handle()["chmpx"]
            if not self._libchmpx:
                raise Exception('unable to load chmpx library')
            self._libk2hdkc = k2hdkc.get_library_handle()["k2hdkc"]
            if not self._libk2hdkc:
                raise Exception('unable to load k2hdkc library')
        except:
            LOG.error("Unexpected error:{%s}", sys.exc_info()[0])
            raise

        self._set_k2h_handle()

    @property
    def libk2hdkc(self):
        """returns libk2hkc handle """
        return self._libk2hdkc

    @property
    def libc(self):
        """returns libc handle """
        return self._libc

    def set(  # noqa: pylint: disable=too-many-branches
            self,
            key,
            val,
            clear_subkeys=False,
            subkeys=None,
            password=None,
            expire_duration=None,
            time_unit=TimeUnit.SECONDS):
        """Sets a key/value pair """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if not isinstance(val, str):
            raise TypeError("val should currently be a str object")

        # checks subkeys
        subkeylist = []
        if subkeys:
            if not isinstance(subkeys, list) and not isinstance(subkeys, str):
                raise TypeError("subkeyes should be a str or list object")
            if isinstance(subkeys, list):
                subkeylist += subkeys
            elif isinstance(subkeys, str):
                subkeylist.append(subkeys)

        if password and not isinstance(password, str):
            raise TypeError("password should be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")
        if time_unit and not isinstance(time_unit, TimeUnit):
            raise TypeError("time_unit should be a TimeUnit object")

        # 1. calls k2hdkc_pm_set_str_all_wa if subkeylist exists
        # bool k2hdkc_pm_set_all_wa(k2hdkc_chmpx_h handle, const unsigned char* pkey, size_t keylength, const unsigned char* pval, size_t vallength, const PK2HDKCKEYPCK pskeypck, int skeypckcnt, const char* encpass, const time_t* expire)
        if len(subkeylist) > 0:
            keypack_array = (k2hdkc.KeyPack * len(subkeylist))()
            i = 0
            for i in subkeylist:
                skey = subkeylist[i]
                skey_bin = skey.encode()
                keypack_array[i].pkey = cast(skey_bin, POINTER(c_ubyte))
                keypack_array[i].length = c_size_t(len(skey_bin) + 1)
                keypack_array_pointer = cast(keypack_array,
                                             POINTER(k2hdkc.KeyPack))
            res = self._libk2hdkc.k2hdkc_pm_set_all_wa(
                self._handle, c_char_p(key.encode()), c_size_t(len(key) + 1),
                c_char_p(val.encode()), c_size_t(len(val) + 1),
                (keypack_array_pointer if keypack_array_pointer else None),
                len(subkeylist),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        else:
            res = self._libk2hdkc.k2hdkc_pm_set_str_value_wa(
                self._handle, c_char_p(key.encode()), c_char_p(val.encode()),
                c_bool(clear_subkeys),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))

        LOG.debug("ret:%s", res)

        # TODO keeps code and subcode or not
        # k2hdkc_get_res_code(self._handle)
        # k2hdkc_get_res_subcode(self._handle)
        return res

    # bool k2hdkc_pm_get_str_value_wp(k2hdkc_chmpx_h handle, const char* pkey, const char* encpass, char** ppval);
    def get(self, key, password=None):
        """Gets the value """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if password and not isinstance(password, str):
            raise TypeError("password should be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        ppval = pointer(c_char_p("".encode()))
        res = self._libk2hdkc.k2hdkc_pm_get_str_value_wp(
            self._handle, c_char_p(key.encode()),
            (c_char_p(password.encode()) if password else None), ppval)

        # TODO keeps code and subcode or not
        # k2hdkc_get_res_code(self._handle)
        # k2hdkc_get_res_subcode(self._handle)

        if res and ppval.contents.value:
            pval = ppval.contents.value.decode()
            if ppval.contents:
                self._libc.free(ppval.contents)
            return pval
        return ""

    # bool k2hdkc_pm_set_str_subkey_wa(k2hdkc_chmpx_h handle, const char* pkey, const char* psubkey, const char* pskeyval, bool checkattr, const char* encpass, const time_t* expire)
    def add_subkey(self,
                   key,
                   subkey,
                   subval,
                   check_attr=True,
                   password=None,
                   expire_duration=None,
                   time_unit=TimeUnit.SECONDS):
        """Adds a new subkey to a current subkey.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if not isinstance(subkey, str):
            raise TypeError("subkey should be a str object")
        if not subkey:
            raise ValueError("subkey should not be empty")
        if not isinstance(subval, str):
            raise TypeError("subval should be a str object")
        if check_attr and not isinstance(check_attr, bool):
            raise TypeError("check_attr should currently be a bool object")
        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")
        if time_unit and not isinstance(time_unit, TimeUnit):
            raise TypeError("time_unit should be a TimeUnit object")

        # bool k2hdkc_pm_set_str_subkey_wa(k2hdkc_chmpx_h handle, const char* pkey, const char* psubkey, const char* pskeyval, bool checkattr, const char* encpass, const time_t* expire)
        res = self._libk2hdkc.k2hdkc_pm_set_str_subkey_wa(
            self._handle,
            c_char_p(key.encode()),
            c_char_p(subkey.encode()),
            c_char_p(subval.encode()),
            c_bool(check_attr),
            (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None),
        )

        if not res:
            LOG.error('error in k2hdkc_pm_set_str_subkey_wa')
        return res

    # bool k2hdkc_pm_cas64_str_get_wa(k2hdkc_chmpx_h handle, const char* pkey, const char* encpass, uint64_t* pval)
    def cas_get(self, key, data_type, password=None, expire_duration=None):  # noqa: pylint: disable=too-many-statements,too-many-branches
        """Gets a variable from a cluster using a CAS operation.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        # data_ type is either byte, short, int or longlong.
        if not data_type:
            raise ValueError("data_type should not be empty")
        if not isinstance(data_type, k2hdkc.DataType):
            raise TypeError("data_type should be a  k2hdkc.DataType object")

        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        if data_type == k2hdkc.DataType.U_BYTE:
            val = c_uint8()
            res = self._libk2hdkc.k2hdkc_pm_cas8_str_get_wa(
                self._handle, c_char_p(key.encode()),
                (c_char_p(password.encode()) if password else None),
                byref(val))
        elif data_type == k2hdkc.DataType.U_SHORT:
            val = c_uint16()
            res = self._libk2hdkc.k2hdkc_pm_cas16_str_get_wa(
                self._handle, c_char_p(key.encode()),
                (c_char_p(password.encode()) if password else None),
                byref(val))
        elif data_type == k2hdkc.DataType.U_INT32:
            val = c_uint32()
            res = self._libk2hdkc.k2hdkc_pm_cas32_str_get_wa(
                self._handle, c_char_p(key.encode()),
                (c_char_p(password.encode()) if password else None),
                byref(val))
        elif data_type == k2hdkc.DataType.U_LONGLONG:
            val = c_ulonglong()
            res = self._libk2hdkc.k2hdkc_pm_cas64_str_get_wa(
                self._handle, c_char_p(key.encode()),
                (c_char_p(password.encode()) if password else None),
                byref(val))
        else:
            raise ValueError(
                "data_type should be a  k2hdkc.DataType object(unknown data_type)"
            )

        if res:
            return val.value
        LOG.error('error in k2hdkc_pm_cas??_str_get_wa')
        return 0

    # bool k2hdkc_pm_cas_str_decrement_wa(k2hdkc_chmpx_h handle, const char* pkey, const char* encpass, const time_t* expire)
    def cas_decrement(self, key, password=None, expire_duration=None):  # noqa: pylint: disable=too-many-branches
        """Decrements a variable in a cluster by using a CAS operation.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        res = self._libk2hdkc.k2hdkc_pm_cas_str_decrement_wa(
            self._handle, c_char_p(key.encode()),
            (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None))
        if not res:
            LOG.error('error in k2hdkc_pm_cas_decrement_wa')
        return res

    # bool k2hdkc_pm_cas_str_increment_wa(k2hdkc_chmpx_h handle, const char* pkey, const char* encpass, const time_t* expire)
    def cas_increment(self, key, password=None, expire_duration=None):  # noqa: pylint: disable=too-many-branches
        """Increments a variable in a cluster by using a CAS operation.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        res = self._libk2hdkc.k2hdkc_pm_cas_str_increment_wa(
            self._handle, c_char_p(key.encode()),
            (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None))
        if not res:
            LOG.error('error in k2hdkc_pm_cas_increment_wa')
        return res

    # bool k2hdkc_pm_cas8_str_init_wa(k2hdkc_chmpx_h handle, const char* pkey, uint8_t val, const char* encpass, const time_t* expire)
    def cas_init(self, key, val=None, password=None, expire_duration=None):  # noqa: pylint: disable=too-many-branches
        """Initializes a variable in a cluster by using a CAS operation.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        # val type is either byte, short, int or longlong.
        if val:
            if not isinstance(val, bytes):
                raise TypeError("val should be a bytes object")
        else:
            val = pack('B', 0)  # default value is 0 in 8bit.

        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        if len(val) == 1:
            res = self._libk2hdkc.k2hdkc_pm_cas8_str_init_wa(
                self._handle, c_char_p(key.encode()),
                c_uint8(unpack('B', val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(val) == 2:
            res = self._libk2hdkc.k2hdkc_pm_cas16_str_init_wa(
                self._handle, c_char_p(key.encode()),
                c_uint16(unpack('H', val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(val) == 4:
            res = self._libk2hdkc.k2hdkc_pm_cas32_str_init_wa(
                self._handle, c_char_p(key.encode()),
                c_uint32(unpack('I', val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(val) == 8:
            res = self._libk2hdkc.k2hdkc_pm_cas64_str_init_wa(
                self._handle, c_char_p(key.encode()),
                c_ulonglong(unpack('Q', val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        if not res:
            LOG.error('error in k2hdkc_pm_cas??_str_init_wa')
        return res

    # bool k2hdkc_pm_cas8_str_set_wa(k2hdkc_chmpx_h handle, const char* pkey, uint8_t oldval, uint8_t newval, const char* encpass, const time_t* expire)
    def cas_set(  # noqa: pylint: disable=too-many-branches
            self,
            key,
            old_val,
            new_val,
            password=None,
            expire_duration=None):
        """Sets a value in a cluster by using a CAS operation.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")
        # val type is either byte, short, int or longlong.
        if not old_val or not new_val:
            raise ValueError("old_val as well as new_val should not be empty")

        if not isinstance(old_val, bytes):
            raise TypeError("old_val should be a bytes object")
        if not isinstance(new_val, bytes):
            raise TypeError("new_val should be a bytes object")
        if len(old_val) != len(new_val):
            raise ValueError(
                "length of old_val and new_val should not be same")

        if password and not isinstance(password, str):
            raise TypeError("password should currently be a str object")
        if password and password == "":
            raise ValueError("password should not be empty")
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a int object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        if len(old_val) == 1:
            res = self._libk2hdkc.k2hdkc_pm_cas8_str_set_wa(
                self._handle, c_char_p(key.encode()),
                c_uint8(unpack('B', old_val)[0]),
                c_uint8(unpack('B', new_val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(old_val) == 2:
            res = self._libk2hdkc.k2hdkc_pm_cas16_str_set_wa(
                self._handle, c_char_p(key.encode()),
                c_uint16(unpack('H', old_val)[0]),
                c_uint16(unpack('H', new_val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(old_val) == 4:
            res = self._libk2hdkc.k2hdkc_pm_cas32_str_set_wa(
                self._handle, c_char_p(key.encode()),
                c_uint32(unpack('I', old_val)[0]),
                c_uint32(unpack('I', new_val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        elif len(old_val) == 8:
            res = self._libk2hdkc.k2hdkc_pm_cas64_str_set_wa(
                self._handle, c_char_p(key.encode()),
                c_uint64(unpack('Q', old_val)[0]),
                c_uint64(unpack('Q', new_val)[0]),
                (c_char_p(password.encode()) if password else None), (pointer(
                    c_uint64(expire_duration)) if expire_duration else None))
        if not res:
            LOG.error('error in k2hdkc_pm_cas??_str_set_wa')
        return res

    # bool k2hdkc_pm_clear_str_subkeys(k2hdkc_chmpx_h handle, const char* pkey)
    def clear_subkeys(self, key):
        """Clears subkeys of a key. Another subkeys that a subkey has will be removed recursively.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")

        res = self._libk2hdkc.k2hdkc_pm_clear_str_subkeys(
            self._handle, c_char_p(key.encode()))

        if not res:
            LOG.error('error in k2hdkc_pm_set_str_subkey_wa')
        return res

    # bool k2hdkc_close_chmpx_ex(k2hdkc_chmpx_h handle, bool is_clean_bup)
    def close(self):
        """Closes the handle
        """
        res = self._libk2hdkc.k2hdkc_close_chmpx_ex(self._handle, c_bool(True))

        if not res:
            LOG.error('error in k2hdkc_close_chmpx_ex')
        return res

    # PK2HDKCATTRPCK k2hdkc_pm_get_str_direct_attrs(k2hdkc_chmpx_h handle, const char* pkey, int* pattrspckcnt)
    def get_attributes(self, key, use_str=True):
        """Retrievs attributes of a key.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")

        pattrspckcnt = c_int()
        res = self._libk2hdkc.k2hdkc_pm_get_str_direct_attrs(
            self._handle, c_char_p(key.encode()), byref(pattrspckcnt))
        LOG.debug("type(res):{%s} pattrspckcnt.value{%s}", type(res),
                  pattrspckcnt.value)
        attrs = {}
        for i in range(pattrspckcnt.value):
            key_buf = ctypes.create_string_buffer(res[i].keylength)
            val_buf = ctypes.create_string_buffer(res[i].vallength)
            for j in range(res[i].keylength):
                key_buf[j] = res[i].pkey[j]
            for k in range(res[i].vallength):
                val_buf[k] = res[i].pval[k]
            if use_str:
                # TODO UnicodeDecodeError occurs calling decode() w/o errors='ignore'
                attrs[key_buf.value.decode()] = val_buf.value.decode(
                    errors='ignore')
            else:
                attrs[key_buf.value] = val_buf.value
        return attrs

    # int k2hdkc_pm_get_str_subkeys(k2hdkc_chmpx_h handle, const char* pkey, char*** ppskeyarray)
    # char** k2hdkc_pm_get_str_direct_subkeys(k2hdkc_chmpx_h handle, const char* pkey)
    # PK2HDKCKEYPCK k2hdkc_pm_get_direct_subkeys(k2hdkc_chmpx_h handle, const unsigned char* pkey, size_t keylength, int* pskeypckcnt)
    # ret.k2hdkc_pm_get_direct_subkeys.argtypes = [
    #     c_uint64, c_char_p, c_size_t,
    #     POINTER(c_int)
    # ]
    # ret.k2hdkc_pm_get_direct_subkeys.restype = POINTER(KeyPack)
    def get_subkeys(self, key, use_str=True):
        """Retrievs subkeys of a key.
        """
        if not isinstance(key, str):
            raise TypeError("key should currently be a str object")
        if not key:
            raise ValueError("key should not be empty")

        pskeypckcnt = c_int()
        res = self._libk2hdkc.k2hdkc_pm_get_direct_subkeys(
            self._handle, c_char_p(key.encode()), c_size_t(len(key) + 1),
            byref(pskeypckcnt))
        LOG.debug("%s", pskeypckcnt.value)
        subkeys = []
        for i in range(pskeypckcnt.value):
            buf = ctypes.create_string_buffer(res[i].length)
            for j in range(res[i].length):
                buf[j] = res[i].pkey[j]
            if use_str:
                subkeys.append(buf.value.decode())
            else:
                subkeys.append(buf.value)
        return subkeys

    # bool k2hdkc_pm_q_str_pop_wp(k2hdkc_chmpx_h handle, const char* pprefix, bool is_fifo, const char* encpass, const char** ppval)
    def queue_get(self,
                  prefix,
                  is_fifo=True,
                  password=None,
                  expire_duration=None):
        """Gets a new element to a queue.
        """
        # prefix
        if not isinstance(prefix, str):
            raise TypeError("prefix should be a string object")
        # fifo
        if not isinstance(is_fifo, bool):
            raise TypeError("fifo should be a boolean object")
        # password
        if password and not isinstance(password, str):
            raise TypeError("password should be a string object")
        # expire_duration
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a boolean object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        ppval = c_char_p()
        res = self._libk2hdkc.k2hdkc_pm_q_str_pop_wp(
            self._handle, c_char_p(prefix.encode()), is_fifo,
            (c_char_p(password.encode()) if password else None), byref(ppval))

        if res and ppval.value:
            pval = ppval.value.decode()
            if ppval:
                self._libc.free(ppval)
            return pval
        return ""

    # bool k2hdkc_pm_q_str_push_wa(k2hdkc_chmpx_h handle, const char* pprefix, const char* pval, bool is_fifo, bool checkattr, const char* encpass, const time_t* expire)
    def queue_put(self,
                  prefix,
                  val,
                  is_fifo=True,
                  is_check_attr=True,
                  password=None,
                  expire_duration=None):
        """Adds a new element to a queue.
        """
        # prefix
        if not isinstance(prefix, str):
            raise TypeError("prefix should be a string object")
        # val
        if not isinstance(val, str):
            raise TypeError("val  should be a string object")
        # fifo
        if not isinstance(is_fifo, bool):
            raise TypeError("fifo should be a boolean object")
        # check_attr
        if not isinstance(is_check_attr, bool):
            raise TypeError("check_attr should be a boolean object")
        # password
        if password and not isinstance(password, str):
            raise TypeError("password should be a string object")
        # expire_duration
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a boolean object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")
        res = self._libk2hdkc.k2hdkc_pm_q_str_push_wa(
            self._handle, c_char_p(prefix.encode()), c_char_p(val.encode()),
            is_fifo, is_check_attr,
            (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None))
        if res:
            LOG.debug("k2hdkc_pm_q_str_push_wa:{%s}", res)
        else:
            return False
        return True

    # bool k2hdkc_pm_keyq_str_pop_wp(k2hdkc_chmpx_h handle, const char* pprefix, bool is_fifo, const char* encpass, const char** ppkey, const char** ppval)
    def keyqueue_get(self,
                     prefix,
                     is_fifo=True,
                     password=None,
                     expire_duration=None):
        """Gets a new key/value element from queue.
        """
        # prefix
        if not isinstance(prefix, str):
            raise TypeError("prefix should be a string object")
        # fifo
        if not isinstance(is_fifo, bool):
            raise TypeError("fifo should be a boolean object")
        # password
        if password and not isinstance(password, str):
            raise TypeError("password should be a string object")
        # expire_duration
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a boolean object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")

        ppkey = c_char_p()
        ppval = c_char_p()
        res = self._libk2hdkc.k2hdkc_pm_keyq_str_pop_wp(
            self._handle, c_char_p(prefix.encode()), is_fifo,
            (c_char_p(password.encode()) if password else None), byref(ppkey),
            byref(ppval))

        if res and ppkey.value and ppval.value:
            pkey = ppkey.value.decode()
            pval = ppval.value.decode()
            if ppkey:
                self._libc.free(ppkey)
            if ppval:
                self._libc.free(ppval)
            return {pkey: pval}
        return {}

    # bool k2hdkc_pm_keyq_str_push_wa(k2hdkc_chmpx_h handle, const char* pprefix, const char* pkey, const char* pval, bool is_fifo, bool checkattr, const char* encpass, const time_t* expire)
    def keyqueue_put(self,
                     prefix,
                     key,
                     val,
                     is_fifo=True,
                     is_check_attr=True,
                     password=None,
                     expire_duration=None):
        """Adds a new key/value pair element to a queue.
        """
        # prefix
        if not isinstance(prefix, str):
            raise TypeError("prefix should be a string object")
        # key
        if not isinstance(key, str):
            raise TypeError("key should be a string object")
        # val
        if not isinstance(val, str):
            raise TypeError("val should be a string object")
        # fifo
        if not isinstance(is_fifo, bool):
            raise TypeError("fifo should be a boolean object")
        # check_attr
        if not isinstance(is_check_attr, bool):
            raise TypeError("check_attr should be a boolean object")
        # password
        if password and not isinstance(password, str):
            raise TypeError("password should be a string object")
        # expire_duration
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a boolean object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")
        res = self._libk2hdkc.k2hdkc_pm_keyq_str_push_wa(
            self._handle, c_char_p(prefix.encode()), c_char_p(key.encode()),
            c_char_p(val.encode()), is_fifo, is_check_attr,
            (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None))
        if res:
            LOG.debug("k2hdkc_pm_keyq_str_push_wa:{%s}", res)
        else:
            return False
        return True

    # bool k2hdkc_pm_remove_str(k2hdkc_chmpx_h handle, const char* pkey)
    def remove(self, key):
        """Removes a key from a cluster.
        """
        if not isinstance(key, str):
            raise TypeError("key should be a str object")
        if not key:
            raise ValueError("key should not be empty")
        res = self._libk2hdkc.k2hdkc_pm_remove_str(self._handle,
                                                   c_char_p(key.encode()))
        return res

    # bool k2hdkc_pm_remove_str_subkey(k2hdkc_chmpx_h handle, const char* pkey, const char* psubkey, size_t subkeylength, bool is_nest)
    def remove_subkeys(self,
                       key,
                       subkeys,
                       nested=False):  # NOTE subkeys accept multiple subkeys
        """Removes a subkey from the current subkeys.
        """
        if not isinstance(key, str):
            raise TypeError("key should be a str object")
        if not key:
            raise ValueError("key should not be empty")
        subkeylist = []
        if not isinstance(subkeys, list) and not isinstance(subkeys, str):
            raise TypeError("subkeyes should be a str or list object")
        if not subkeys:
            raise ValueError("subkeys should not be empty")
        if isinstance(subkeys, list):
            subkeylist += deepcopy(subkeys)
        elif isinstance(subkeys, str):
            subkeylist.append(subkeys)
        if not isinstance(nested, bool):
            raise TypeError("nested should be a boolean object")

        for subkey in subkeylist:
            if not isinstance(subkey, str):
                LOG.warning("subkey should be a str object")
                continue
            if not subkey:
                LOG.warning("subkey should not be empty")
                continue
            res = self._libk2hdkc.k2hdkc_pm_remove_str_subkey(
                self._handle, c_char_p(key.encode()),
                c_char_p(subkey.encode()), c_bool(nested))
            if not res:
                return False
        return True

    # bool k2hdkc_pm_rename_with_parent_str_wa(k2hdkc_chmpx_h handle, const char* poldkey, const char* pnewkey, const char* pparentkey, bool checkattr, const char* encpass, const time_t* expire)
    def rename(self,
               key,
               newkey,
               parent_key=None,
               is_check_attr=True,
               password=None,
               expire_duration=None):
        """Renames a key in a cluster.
        """
        if not isinstance(key, str):
            raise TypeError("key should be a str object")
        if not key:
            raise ValueError("key should not be empty")
        if not isinstance(newkey, str):
            raise TypeError("newkey should be a str object")
        if not newkey:
            raise ValueError("newkey should not be empty")
        if parent_key and not isinstance(parent_key, str):
            raise TypeError("parent_key should be a str object")
        # check_attr
        if not isinstance(is_check_attr, bool):
            raise TypeError("check_attr should be a boolean object")
        # password
        if password and not isinstance(password, str):
            raise TypeError("password should be a string object")
        # expire_duration
        if expire_duration and not isinstance(expire_duration, int):
            raise TypeError("expire_duration should be a boolean object")
        if expire_duration and expire_duration <= 0:
            raise ValueError("expire_duration should not be positive")
        res = self._libk2hdkc.k2hdkc_pm_rename_with_parent_str_wa(
            self._handle, c_char_p(key.encode()), c_char_p(newkey.encode()),
            (c_char_p(parent_key.encode()) if parent_key else None),
            is_check_attr, (c_char_p(password.encode()) if password else None),
            (pointer(c_uint64(expire_duration)) if expire_duration else None))
        return res

    def set_subkeys(self, key, subkeys):
        """Replaces current subkeys with new one.
        """
        if not isinstance(key, str):
            raise TypeError("key should be a str object")
        if not key:
            raise ValueError("key should not be empty")
        subkeylist = []
        if not isinstance(subkeys, list) and not isinstance(subkeys, str):
            raise TypeError("subkeyes should be a str or list object")
        if not subkeys:
            raise ValueError("subkeys should not be empty")
        if isinstance(subkeys, list):
            subkeylist += subkeys
        elif isinstance(subkeys, str):
            subkeylist.append(subkeys)

        if len(subkeylist) > 0:
            keypack_array = (k2hdkc.KeyPack * len(subkeylist))()
            i = 0
            for i in subkeylist:
                skey = subkeylist[i]
                skey_bin = skey.encode()
                keypack_array[i].pkey = cast(skey_bin, POINTER(c_ubyte))
                keypack_array[i].length = c_size_t(len(skey_bin) + 1)
            keypack_array_pointer = cast(keypack_array,
                                         POINTER(k2hdkc.KeyPack))

        # bool k2hdkc_pm_set_subkeys(k2hdkc_chmpx_h handle, const unsigned char* pkey, size_t keylength, const PK2HDKCKEYPCK pskeypck, int skeypckcnt)
        key_bin = key.encode()
        res = self._libk2hdkc.k2hdkc_pm_set_subkeys(
            self._handle, cast(key_bin, POINTER(c_ubyte)),
            c_size_t(len(key_bin) + 1),
            (keypack_array_pointer if keypack_array_pointer else None),
            len(subkeylist))
        return res


#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
