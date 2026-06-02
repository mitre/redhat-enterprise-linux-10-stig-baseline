control 'SV-281266' do
  title 'RHEL 10 must not allow a noncertificate trusted host Secure Shell (SSH) login to the system.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 does not allow a noncertificate trusted host SSH login to the system with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*hostbasedauthentication'
/etc/ssh/sshd_config.d/10-stig.conf:HostbasedAuthentication no

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i hostbasedauthentication
hostbasedauthentication no

If the "HostbasedAuthentication" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, or no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to not allow a noncertificate trusted host SSH login to the system.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

HostbasedAuthentication no

Restart the SSH daemon with the following command for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85827r1166748_chk'
  tag severity: 'medium'
  tag gid: 'V-281266'
  tag rid: 'SV-281266r1184766_rule'
  tag stig_id: 'RHEL-10-700630'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85732r1166749_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('HostBasedAuthentication') { should cmp 'no' }
  end
end
