
# install_octavia_tempest_plugin
function install_octavia_tempest_plugin {
    setup_dev_lib "octavia-tempest-plugin"
}

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            echo_summary "Installing octavia-tempest-plugin"
            install_octavia_tempest_plugin
            ;;
    esac
fi
