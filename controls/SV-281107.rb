control 'SV-281107' do
  title 'RHEL 10 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity.'
  desc 'If action is not taken when storage volume reaches 95 percent utilization, the auditing system may fail when the storage volume reaches capacity.'
  desc 'check', 'Verify RHEL 10 takes action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w admin_space_left /etc/audit/auditd.conf
admin_space_left = 5%

If the value of the "admin_space_left" keyword is not set to 5 percent of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator to indicate how the system is taking action if the allocated storage is about to reach capacity. 

If the "space_left" value is not configured to the correct value, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to initiate an action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file:

admin_space_left = 5%

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85668r1166271_chk'
  tag severity: 'medium'
  tag gid: 'V-281107'
  tag rid: 'SV-281107r1166273_rule'
  tag stig_id: 'RHEL-10-500105'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-85573r1166272_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  admin_space_left = input('admin_space_left')

  describe auditd_conf do
    its('admin_space_left') { should cmp admin_space_left }
  end
end
