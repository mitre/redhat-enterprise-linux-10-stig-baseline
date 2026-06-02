control 'SV-281105' do
  title 'RHEL 10 must label all off-loaded audit logs before sending them to the central log server.'
  desc 'Enriched logging is needed to determine who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.

When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.'
  desc 'check', 'Verify the RHEL 10 audit daemon is configured to label all off-loaded audit logs with the following command:

$ sudo grep name_format /etc/audit/auditd.conf
name_format = hostname

If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that all off-loaded audit logs are labeled before sending them to the central log server.

Edit the "/etc/audit/auditd.conf" file and add or update the "name_format" option:

name_format = hostname

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag gid: 'V-281105'
  tag rid: 'SV-281105r1166267_rule'
  tag stig_id: 'RHEL-10-500045'
  tag fix_id: 'F-85571r1166266_fix'
  tag cci: ['CCI-001851', 'CCI-000132']
  tag nist: ['AU-4 (1)', 'AU-3 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('name_format') { should match(/^hostname$|^fqd$|^numeric$/i) }
  end
end
