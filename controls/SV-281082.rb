control 'SV-281082' do
  title 'RHEL 10 must define default permissions for all authenticated users in such a way that the user can read and modify only their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new
accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify RHEL 10 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files with the following command:

Note: If the value of the "umask" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

$ sudo grep -i umask /etc/login.defs
umask 077

If the value for the "umask" parameter is not "077", or the "umask" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to define default permissions for all authenticated users in such a way that the user can read and modify only their own files.

Add or edit the lines for the "umask" parameter in the "/etc/login.defs" file to "077":

umask 077'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-281082'
  tag rid: 'SV-281082r1195406_rule'
  tag stig_id: 'RHEL-10-400325'
  tag fix_id: 'F-85548r1195405_fix'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'
  tag 'container'

  modes_for_shells = input('modes_for_shells')

  describe login_defs do
    its('UMASK') { should cmp modes_for_shells['default_umask'] }
  end
end
