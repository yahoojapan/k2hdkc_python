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

import unittest
import k2hdkc
import logging


class TestK2hdkcPackage(unittest.TestCase):
    def test_get_library_handle(self):
        libk2hdkc = k2hdkc.get_library_handle()
        self.assertTrue(libk2hdkc)
        self.assertTrue(isinstance(libk2hdkc, dict))
        self.assertTrue(libk2hdkc['c'])
        self.assertTrue(libk2hdkc['k2hdkc'])

    def test_set_log_level(self):
        k2hdkc.set_log_level(logging.INFO)
        logger = logging.getLogger('k2hdkc')
        self.assertEqual(logging.getLevelName(logger.level), 'INFO')

    def test_set_layer_log_level(self):
        self.assertEqual(
            k2hdkc.set_layer_log_level(k2hdkc.LayerLogLevel.K2HDKC), True)


if __name__ == '__main__':
    unittest.main()

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
