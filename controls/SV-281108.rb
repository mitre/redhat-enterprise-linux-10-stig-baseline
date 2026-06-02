control 'SV-281108' do
  title 'RHEL 10 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity.'
  desc 'If action is not taken when storage volume reaches 95 percent utilization, the auditing system may fail when the storage volume reaches capacity.'
  desc 'check', 'Verify RHEL 10 is configured to take action if allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep admin_space_left_action /etc/audit/auditd.conf
admin_space_left_action = single

If the value of the "admin_space_left_action" is not set to "single", or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO).

If there is no evidence that real-time alerts are configured on the system, this is a finding.'
  desc 'fix', 'Configure RHEL 10 auditd service to take action if allocated audit record storage volume reaching 95 percent of the repository maximum audit record storage capacity.

Edit the following line in "/etc/audit/auditd.conf" to ensure the system is forced into single user mode if the audit record storage volume is about to reach maximum capacity:

admin_space_left_action = single

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85669r1166274_chk'
  tag severity: 'medium'
  tag gid: 'V-281108'
  tag rid: 'SV-281108r1166276_rule'
  tag stig_id: 'RHEL-10-500110'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-85574r1166275_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  admin_space_left_action = input('admin_space_left_action').upcase

  describe auditd_conf do
    its('admin_space_left_action.upcase') { should cmp admin_space_left_action }
  end
end
