# A throwaway "customer server" for testing install.sh end to end: real
# systemd as PID 1, so the installer's user creation, unit file and hardening
# all run for real.
#
#   docker build -t sentinel-test-host deploy/testing/systemd-host
#   docker run -d --name pg-host --privileged --cgroupns=host \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw sentinel-test-host
#   docker exec pg-host sh -c 'curl -fsSL <api>/install.sh | sh -s -- --key pg_...'
FROM ubuntu:24.04
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && : > /etc/machine-id  # each container gets its own at boot, like a properly sealed template

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
