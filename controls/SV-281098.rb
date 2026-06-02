control 'SV-281098' do
  title 'RHEL 10 must audit local events.'
  desc 'Without establishing what type of events occurred, along with the source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

If option "local_events" is not set to "yes", only events from the network will be aggregated.'
  desc 'check', 'Verify that RHEL 10 generates audit records for local events with the following command:

$ sudo grep local_events /etc/audit/auditd.conf
local_events = yes

If "local_events" is not set to "yes", the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records for local events by adding or updating the following line in "/etc/audit/auditd.conf":

local_events = yes

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag gid: 'V-281098'
  tag rid: 'SV-281098r1165649_rule'
  tag stig_id: 'RHEL-10-500010'
  tag fix_id: 'F-85564r1165648_fix'
  tag cci: ['CCI-000366', 'CCI-000169']
  tag nist: ['CM-6 b', 'AU-12 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('local_events') { should eq 'yes' }
  end
end
