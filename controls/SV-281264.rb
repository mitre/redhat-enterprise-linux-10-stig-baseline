control 'SV-281264' do
  title 'RHEL 10 must be configured so that SSHD does not allow blank passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.

'
  desc 'check', %q(Verify RHEL 10 remote access using SSH prevents logging on with a blank password with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permitemptypasswords'
/etc/ssh/sshd_config.d/10-stig.conf:PermitEmptyPasswords no

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i permitemptypasswords
permitemptypasswords no

If the "PermitEmptyPasswords" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to prevent SSH users from logging on with blank passwords. 

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

PermitEmptyPasswords no

Restart the SSH daemon with the following command for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85825r1166742_chk'
  tag severity: 'medium'
  tag gid: 'V-281264'
  tag rid: 'SV-281264r1184764_rule'
  tag stig_id: 'RHEL-10-700610'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-85730r1166743_fix'
  tag satisfies: ['SRG-OS-000106-GPOS-00053', 'SRG-OS-000480-GPOS-00229']
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end
