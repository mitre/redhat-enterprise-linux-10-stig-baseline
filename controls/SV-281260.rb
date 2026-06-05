control 'SV-281260' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon displays the date and time of the last successful account login upon an SSH login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH daemons provide users with feedback on when account accesses last occurred with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*printlastlog'
/etc/ssh/sshd_config.d/10-stig.conf:PrintLastLog yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i printlastlog
printlastlog yes

If the "PrintLastLog" keyword is not set to "yes" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to provide users with feedback on when account accesses last occurred.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

PrintLastLog yes

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85821r1166730_chk'
  tag severity: 'medium'
  tag gid: 'V-281260'
  tag rid: 'SV-281260r1184760_rule'
  tag stig_id: 'RHEL-10-700570'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85726r1166731_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  if %w[docker podman kubepods lxc].include?(virtualization.system) && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('PrintLastLog') { should cmp 'yes' }
    end
  end
end
