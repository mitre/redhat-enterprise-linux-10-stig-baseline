control 'SV-281261' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon prevents remote hosts from connecting to the proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the "DISPLAY" environment variable to localhost. This prevents remote hosts from connecting to the proxy display.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH daemons prevent remote hosts from connecting to the proxy display with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11uselocalhost'
/etc/ssh/sshd_config.d/10-stig.conf:X11UseLocalhost yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i x11uselocalhost
x11uselocalhost yes

If the "X11UseLocalhost" keyword is not set to "yes" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to prevent remote hosts from connecting to the proxy display.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

X11UseLocalhost yes

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85822r1166733_chk'
  tag severity: 'medium'
  tag gid: 'V-281261'
  tag rid: 'SV-281261r1184761_rule'
  tag stig_id: 'RHEL-10-700580'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85727r1166734_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  describe sshd_config do
    its('X11UseLocalhost') { should cmp 'yes' }
  end
end
