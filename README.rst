==============
k2hdkc_python
==============

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
        :target: https://github.com/yahoojapan/k2hdkc_python/blob/master/LICENSE
.. image:: https://img.shields.io/pypi/pyversions/k2hdkc.svg
        :target: https://pypi.python.org/pypi/k2hdkc
.. image:: https://img.shields.io/github/forks/yahoojapan/k2hdkc_python.svg
        :target: https://github.com/yahoojapan/k2hdkc_python/network
.. image:: https://img.shields.io/github/stars/yahoojapan/k2hdkc_python.svg
        :target: https://github.com/yahoojapan/k2hdkc_python/stargazers
.. image:: https://img.shields.io/github/issues/yahoojapan/k2hdkc_python.svg
        :target: https://github.com/yahoojapan/k2hdkc_python/issues
.. image:: https://github.com/yahoojapan/k2hdkc_python/workflows/Python%20package/badge.svg
        :target: https://github.com/yahoojapan/k2hdkc_python/actions
.. image:: https://readthedocs.org/projects/k2hdkc-python/badge/?version=latest
        :target: https://k2hdkc-python.readthedocs.io/en/latest/?badge=latest
.. image:: https://img.shields.io/pypi/v/k2hdkc
        :target: https://pypi.org/project/k2hdkc/



Overview
---------

k2hdkc_python is an official python driver for `k2hdkc`_.

.. _`k2hdkc`: https://k2hdkc.antpick.ax/

.. image:: https://raw.githubusercontent.com/yahoojapan/k2hdkc_python/main/docs/images/top_k2hdkc_python.png


Install
--------

Let's install k2hdkc using pip::

    pip install k2hdkc


Usage
------

Firstly you must install the k2hdkc shared library::

    $ curl -o- https://raw.github.com/yahoojapan/k2hdkc_python/master/cluster/start_server.sh | bash


Then, Let's try to set a key and get it::

    import k2hdkc
    
    k = k2hdkc.K2hdkc('slave.yaml')
    k.set('hello', 'world')
    v = k.get('hello')
    print(v)    // world


Development
------------

Clone this repository and go into the directory, then run the following command::

    $ python3 -m pip install --upgrade build
    $ python3 -m build


Documents
----------

Here are documents including other components.

`Document top page`_

`About K2HDKC`_

`About AntPickax`_

.. _`Document top page`: https://k2hdkc-python.readthedocs.io/
.. _`ドキュメントトップ`: https://k2hdkc-python.readthedocs.io/
.. _`About K2HDKC`: https://k2hdkc.antpick.ax/
.. _`K2HDKCについて`: https://k2hdkc.antpick.ax/
.. _`About AntPickax`: https://antpick.ax
.. _`AntPickaxについて`: https://antpick.ax


Packages
--------

Here are packages including other components.

`k2hdkc(python packages)`_

.. _`k2hdkc(python packages)`:  https://pypi.org/project/k2hdkc/


License
--------

MIT License. See the LICENSE file.

AntPickax
---------

**k2hdkc_python** is a project by AntPickax_, which is an open source team in `Yahoo Japan Corporation`_.

.. _AntPickax: https://antpick.ax/
.. _`Yahoo Japan Corporation`: https://about.yahoo.co.jp/info/en/company/

