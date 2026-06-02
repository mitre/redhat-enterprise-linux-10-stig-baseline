control 'SV-281109' do
  title 'RHEL 10 must take appropriate action when the internal event queue is full.'
  desc 'The audit system must have an action set up in case the internal event queue becomes full so that no data is lost. Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the RHEL 10 audit system is configured to take an appropriate action when the internal event queue is full:

$ sudo grep overflow_action /etc/audit/auditd.conf
overflow_action = syslog

If the value of the "overflow_action" option is not set to "syslog", "single", or "halt", or the line is commented out, ask the system administrator to indicate how the audit logs are off-loaded to a different system or media.

If there is no evidence that the audit system is configured to off-load the audit logs to another system or media, and if the overflow action is not set to take appropriate action if the internal event queue becomes full, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to take appropriate action when the internal event queue is full.

Edit the "/etc/audit/auditd.conf" file and add or update the "overflow_action" option:

overflow_action = syslog

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-281109'
  tag rid: 'SV-281109r1184691_rule'
  tag stig_id: 'RHEL-10-500115'
  tag fix_id: 'F-85575r1166278_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('overflow_action') { should match(/syslog$|single$|halt$/i) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
