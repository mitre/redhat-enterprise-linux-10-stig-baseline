control 'SV-281110' do
  title 'RHEL 10 must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without establishing what type of events occurred, along with the source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging aids in making sense of who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.'
  desc 'check', 'Verify the RHEL 10 audit system is configured to resolve audit information before writing to disk with the following command:

$ sudo grep log_format /etc/audit/auditd.conf
log_format = ENRICHED

If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 audit system to resolve audit information before writing to disk.

Edit the "/etc/audit/auditd.conf" file and add or update the "log_format" option:

log_format = ENRICHED

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag gid: 'V-281110'
  tag rid: 'SV-281110r1166282_rule'
  tag stig_id: 'RHEL-10-500120'
  tag fix_id: 'F-85576r1166281_fix'
  tag cci: ['CCI-000366', 'CCI-001487']
  tag nist: ['CM-6 b', 'AU-3 f']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('log_format') { should eq 'ENRICHED' }
  end
end
