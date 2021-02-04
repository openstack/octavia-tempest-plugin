#!/usr/bin/env bash

saveenv=$-
set -e

# install_octavia_tempest_plugin
function install_octavia_tempest_plugin {
    setup_dev_lib "octavia-tempest-plugin"
}

function build_backend_test_server {
    if is_fedora || is_ubuntu; then
        install_package golang
    else
        die "Distribution not supported. Supported distributions are: RHEL, CentOS, Fedora, Ubuntu"
    fi

    go_path=$(find $DEST/tempest/.tox/tempest/ -name test_server.go)
    sudo mkdir -m755 -p /opt/octavia-tempest-plugin
    sudo chown $STACK_USER /opt/octavia-tempest-plugin
    CGO_ENABLED=0 GOOS=linux go build \
        -a -ldflags '-s -w -extldflags -static' \
        -o /opt/octavia-tempest-plugin/test_server.bin \
        ${DEST}/octavia-tempest-plugin/octavia_tempest_plugin/contrib/test_server/test_server.go
}

function _configure_tempest {
    if [ -n "$Q_ROUTER_NAME" ]; then
        iniset $TEMPEST_CONFIG load_balancer default_router "$Q_ROUTER_NAME"
    fi
    if [ -n "$SUBNETPOOL_NAME_V6" ]; then
        iniset $TEMPEST_CONFIG load_balancer default_ipv6_subnetpool "$SUBNETPOOL_NAME_V6"
    fi
}

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            # Install dev library if
            # - the release is more recent than train (devstack in train would
            #   try to install it in a python2 env, but octavia-tempest-plugin
            #   is now a python3-only project)
            # - or the user explicitly requests it (INSTALL_TEMPEST=True)
            if [[ ! "$DEVSTACK_SERIES" =~ (stein|train) ]] || [[ "$(trueorfalse False INSTALL_TEMPEST)" == "True" ]]; then
                echo_summary "Installing octavia-tempest-plugin"
                install_octavia_tempest_plugin
            fi
            ;;
        test-config)
            echo_summary "Building backend test server"
            build_backend_test_server
            _configure_tempest
            ;;
    esac
fi

if [[ $saveenv =~ e ]]; then
    set -e
else
    set +e
fi
