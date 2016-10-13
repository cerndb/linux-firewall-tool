Host config
===========

**Example of applying a configuration to a host**

    .. code-block:: ini

        [apache]
        machines = "test.sh"
        default_parameters = ['no_default_config','deploy']
        default_interface = main
        config_folder = /root/cerndb-infra-firewall/custom_conf_files
        config_folder_files = ['example_config_1.cfg','example_config_3.cfg','example_config_6.cfg']
        config_files = ['/root/cerndb-infra-firewall/custom_conf_files/example_config_7.cfg']