.. linux-firewall-tool documentation master file, created by
   sphinx-quickstart on Tue Sep 13 16:11:30 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

linux-firewall-tool
==========================

Summary
=======
The current tool is managing **iptables**, **ip6tables** using **ipsets**. It is created to simplify the Linux firewall
configuration at CERN IT Databases Group. It is intended to help SysAdmins that manage firewalls and make changes
regularly. It works by parsing simple **.ini** files which include the configuration in order to build the iptables
rules and kernel ipesets.

Contents
========

.. toctree::
    :maxdepth: 4
    :name: mastertoc

    examples
    code
    config
    scripts




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

