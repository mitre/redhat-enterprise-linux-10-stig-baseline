control 'SV-281267' do
  title 'RHEL 10 must not allow users to override Secure Shell (SSH) environment variables.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 disables unattended or automatic login via SSH with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permituserenvironment'
/etc/ssh/sshd_config.d/10-stig.conf:PermitUserEnvironment no

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i permituserenvironment
permituserenvironment no

If the "PermitUserEnvironment" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to disable unattended or automatic login via SSH.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

PermitUserEnvironment no

Restart the SSH daemon with the following command for the setting to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-85828r1166751_chk'
  tag severity: 'high'
  tag gid: 'V-281267'
  tag rid: 'SV-281267r1184767_rule'
  tag stig_id: 'RHEL-10-700640'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85733r1166752_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  only_if('This requirement is Not Applicable inside a container, the containers host manages the containers filesystems') {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end
