control 'SV-281256' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon does not allow rhosts authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH daemons do not allow rhosts authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ignorerhosts'
/etc/ssh/sshd_config.d/10-stig.conf:IgnoreRhosts yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i ignorerhosts
ignorerhosts yes

If the "IgnoreRhosts" keyword is not set to "yes" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to not allow rhosts authentication.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

IgnoreRhosts yes

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85817r1166718_chk'
  tag severity: 'medium'
  tag gid: 'V-281256'
  tag rid: 'SV-281256r1184756_rule'
  tag stig_id: 'RHEL-10-700530'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85722r1166719_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('IgnoreRhosts') { should cmp 'yes' }
  end
end
