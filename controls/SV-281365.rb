control 'SV-281365' do
  title 'RHEL 10 must prevent unauthorized changes to the audit system.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 10 system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable, and a system administrator could then investigate the unauthorized changes.

'
  desc 'check', 'Verify the RHEL 10 audit system prevents unauthorized changes with the following command:

$ sudo grep "^\\s*[^#]" /etc/audit/audit.rules | tail -1
-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the end of "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to protect the audit system from unauthorized changes.

Set the audit rules to be immutable by adding the following line to end of "/etc/audit/rules.d/audit.rules":

-e 2

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85926r1167243_chk'
  tag severity: 'medium'
  tag gid: 'V-281365'
  tag rid: 'SV-281365r1167245_rule'
  tag stig_id: 'RHEL-10-900100'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85831r1167244_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe command('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1') do
    its('stdout.strip') { should cmp '-e 2' }
  end
end
