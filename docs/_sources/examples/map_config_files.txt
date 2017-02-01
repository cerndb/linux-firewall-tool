Visual mapping of config files
==============================


** Mapping the files **

On both scripts (**host_manager.py** and **iptables_manager.py**) there is an argument from command line.

For **host_manager.py** the arguent is **--map_hostfile** which generates dot language code in order to visualize host
file contents under this path: **/var/tmp/firewall_files/host_map.dot**

For **iptables_manager.py** the argument is **--map_config_files** which generates dot language code in order to visualize
host file contents under this path: **/var/tmp/firewall_files/rules_map.dot**

On both cases you of course provide a list of config files using the **--config** argument.

Simply copy the contents of those file to an online tool such as https://mdaines.github.io/viz.js/
or use dot language compiler on your machine in order to see the visualization