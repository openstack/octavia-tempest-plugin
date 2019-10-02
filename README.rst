======================
Octavia Tempest Plugin
======================

Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/octavia-tempest-plugin.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

Tempest integration of Octavia
==============================

This project contains the Tempest plugin for the Octavia project for
OpenStack Load Balancing.

For more information about Octavia see:
https://docs.openstack.org/octavia/latest/

For more information about Tempest plugins see:
https://docs.openstack.org/tempest/latest/plugin.html

* Free software: Apache license
* Documentation: https://docs.openstack.org/octavia-tempest-plugin/latest/
* Source: https://opendev.org/openstack/octavia-tempest-plugin
* Bugs: https://storyboard.openstack.org/#!/project/openstack/octavia-tempest-plugin

Installing
----------

Clone this repository to the destination machine, and call from the repo::

    $ pip install -e .

Running the tests
-----------------

To run all the tests from this plugin, call from the tempest repo::

    $ tox -e all-plugin -- octavia_tempest_plugin

To run a single test case, call with full path, for example::

    $ tox -e all-plugin -- octavia_tempest_plugin.tests.scenario.v2.test_traffic_ops.TrafficOperationsScenarioTest.test_basic_traffic

To retrieve a list of all tempest tests, run::

    $ testr list-tests
