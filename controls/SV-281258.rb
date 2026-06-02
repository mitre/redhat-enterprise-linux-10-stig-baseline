control 'SV-281258' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon disables remote X connections for interactive users.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH daemons do not allow X11Forwarding with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11forwarding'
/etc/ssh/sshd_config.d/10-stig.conf:X11forwarding no
/etc/ssh/sshd_config.d/50-redhat.conf:X11Forwarding yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i x11forwarding
x11forwarding no

If the "X11forwarding" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, and X11 forwarding is not documented with the information system security officer as an operational requirement, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to not allow X11 forwarding.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

X11forwarding no

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85819r1166724_chk'
  tag severity: 'medium'
  tag gid: 'V-281258'
  tag rid: 'SV-281258r1184758_rule'
  tag stig_id: 'RHEL-10-700550'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85724r1166725_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
