control 'SV-281259' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon performs strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log in to the system as another user.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH daemons perform strict mode checking of home directory configuration files with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*strictmodes'
/etc/ssh/sshd_config.d/10-stig.conf:StrictModes yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i strictmodes
strictmodes yes

If the "StrictModes" keyword is not set to "yes" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to perform strict mode checking of home directory configuration files.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

StrictModes yes

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85820r1166727_chk'
  tag severity: 'medium'
  tag gid: 'V-281259'
  tag rid: 'SV-281259r1184759_rule'
  tag stig_id: 'RHEL-10-700560'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85725r1166728_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('StrictModes') { should cmp 'yes' }
  end
end
