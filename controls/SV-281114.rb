control 'SV-281114' do
  title 'RHEL 10 must notify the system administrator (SA) and/or information system security officer (ISSO) (at a minimum) of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

'
  desc 'check', 'Verify RHEL 10 is configured to notify the SA and/or ISSO (at a minimum) of an audit processing failure with the following command:

$ sudo grep action_mail_acct /etc/audit/auditd.conf
action_mail_acct = root

If the value of the "action_mail_acct" keyword is not set to "root" and/or other accounts for security personnel, the "action_mail_acct" keyword is missing, or the retuned line is commented out, ask the SA to indicate how they and the ISSO are notified of an audit process failure. 

If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to notify the SA and/or ISSO (at a minimum) of an audit processing failure.

Edit the following line in "/etc/audit/auditd.conf" to ensure administrators are notified via email for those situations:

action_mail_acct = root

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85675r1166292_chk'
  tag severity: 'medium'
  tag gid: 'V-281114'
  tag rid: 'SV-281114r1166294_rule'
  tag stig_id: 'RHEL-10-500210'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-85580r1166293_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000343-GPOS-00134']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-001855']
  tag nist: ['AU-5 a', 'AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe auditd_conf do
    its('action_mail_acct') { should cmp 'root' }
  end
end
