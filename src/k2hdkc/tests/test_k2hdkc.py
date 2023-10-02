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

import ctypes
import logging
import time
import unittest
from struct import pack

import k2hdkc


class TestK2hdkc(unittest.TestCase):
    def test_K2hdkc_construct(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        db.close()

    def test_K2hdkc_add_subkey(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        subkey = "sub_hello"
        subval = "sub_world"
        self.assertTrue(db.add_subkey(key, subkey, subval), True)
        self.assertTrue(db.get_subkeys(key), [subkey])
        db.close()

    def test_K2hdkc_clear_subkeys(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        subkey = "sub_hello"
        subval = "sub_world"
        self.assertTrue(db.add_subkey(key, subkey, subval), True)
        self.assertTrue(db.get_subkeys(key), [subkey])
        self.assertTrue(db.clear_subkeys(key), True)
        # TODO error
        # self.assertTrue(db.get_subkeys(key), [])
        db.close()

    def test_K2hdkc_get(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        db.close()

    @unittest.skip("skipping because no attrs")
    def test_K2hdkc_get_attrs(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        db.close()

    def test_K2hdkc_get_subkeys(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        subkey = "sub_hello"
        subval = "sub_world"
        self.assertTrue(db.add_subkey(key, subkey, subval), True)
        self.assertTrue(db.get_subkeys(key), [subkey])
        db.close()

    def test_K2hdkc_queue_get(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        qkey = "q_hello"
        qval = "q_world"
        self.assertTrue(db.queue_put(qkey, qval), True)
        self.assertTrue(db.queue_get(qkey), qval)
        db.close()

    def test_K2hdkc_queue_put(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        qkey = "q_hello"
        qval = "q_world"
        self.assertTrue(db.queue_put(qkey, qval), True)
        self.assertTrue(db.queue_get(qkey), qval)
        db.close()

    def test_K2hdkc_keyqueue_get(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        qprefix = "q_prefix"
        qkey = "q_hello"
        qval = "q_world"
        self.assertTrue(db.keyqueue_put(qprefix, qkey, qval), True)
        self.assertTrue(db.keyqueue_get(qprefix), {qkey, qval})
        db.close()

    def test_K2hdkc_keyqueue_put(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        qprefix = "q_prefix"
        qkey = "q_hello"
        qval = "q_world"
        self.assertTrue(db.keyqueue_put(qprefix, qkey, qval), True)
        self.assertTrue(db.keyqueue_get(qprefix), {qkey, qval})
        db.close()

    def test_K2hdkc_remove(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        self.assertTrue(db.remove(key), True)
        self.assertFalse(db.get(key), val)
        db.close()

    def test_K2hdkc_remove_subkeys(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        subkey = "sub_hello"
        subval = "sub_world"
        self.assertTrue(db.add_subkey(key, subkey, subval), True)
        self.assertTrue(db.get_subkeys(key), [subkey])
        # TODO error
        # self.assertTrue(db.remove_subkeys(key, subkey), True)
        db.close()

    def test_K2hdkc_rename(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        newkey = "olleh"
        self.assertTrue(db.rename(key, newkey), True)
        self.assertTrue(db.get(newkey), val)
        db.close()

    def test_K2hdkc_set(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        db.close()

    def test_K2hdkc_set_subkeys(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        subkey = "sub_hello"
        subval = "sub_world"
        self.assertTrue(db.add_subkey(key, subkey, subval), True)
        self.assertTrue(db.get_subkeys(key), [subkey])
        db.close()

    def test_K2hdkc_cas_init(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        cas_key = "cas_hello"
        cas_value = 65530
        self.assertTrue(db.cas_init(cas_key, pack("H", cas_value)), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        db.close()

    def test_K2hdkc_cas_get(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        cas_key = "cas_hello"
        cas_value = 65530
        self.assertTrue(db.cas_init(cas_key, pack("H", cas_value)), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        db.close()

    def test_K2hdkc_cas_decrement(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        cas_key = "cas_hello"
        cas_value = 65530
        self.assertTrue(db.cas_init(cas_key, pack("H", cas_value)), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        self.assertTrue(db.cas_increment(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value + 1)
        self.assertTrue(db.cas_decrement(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        db.close()

    def test_K2hdkc_cas_increment(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        cas_key = "cas_hello"
        cas_value = 65530
        self.assertTrue(db.cas_init(cas_key, pack("H", cas_value)), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        self.assertTrue(db.cas_increment(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value + 1)
        self.assertTrue(db.cas_decrement(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        db.close()

    def test_K2hdkc_cas_set(self):
        db = k2hdkc.K2hdkc("/tmp/slave.yaml")
        self.assertTrue(isinstance(db, k2hdkc.K2hdkc))
        key = "hello"
        val = "world"
        self.assertTrue(db.set(key, val), True)
        self.assertTrue(db.get(key), val)
        cas_key = "cas_hello"
        cas_value = 65530
        self.assertTrue(db.cas_init(cas_key, pack("H", cas_value)), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        self.assertTrue(db.cas_increment(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value + 1)
        self.assertTrue(db.cas_decrement(cas_key), True)
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), cas_value)
        new_cas_value = 1
        self.assertTrue(
            db.cas_set(cas_key, pack("H", cas_value), pack("H", new_cas_value)), True
        )
        self.assertTrue(db.cas_get(cas_key, k2hdkc.DataType.U_SHORT), new_cas_value)
        db.close()


if __name__ == "__main__":
    unittest.main()

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
