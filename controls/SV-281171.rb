control 'SV-281171' do
  title 'RHEL 10 must assign a home directory for local interactive user accounts upon creation.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify RHEL 10 assigns a home directory for local interactive user accounts upon creation with the following command:

$ sudo grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows:

CREATE_HOME yes'
  impact 0.5
  tag check_id: 'C-85732r1166463_chk'
  tag severity: 'medium'
  tag gid: 'V-281171'
  tag rid: 'SV-281171r1166465_rule'
  tag stig_id: 'RHEL-10-600120'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-85637r1166464_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('CREATE_HOME') { should eq 'yes' }
  end
end
