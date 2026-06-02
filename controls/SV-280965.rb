control 'SV-280965' do
  title 'RHEL 10 must enable audit logging for the USBGuard daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DOD has defined the list of events for which RHEL 10 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).

2) Access actions, such as successful and unsuccessful login attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logins from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.

3) All account creations, modifications, disabling, and terminations.

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Note: If the system is a virtual machine with no virtual or physical USB peripherals attached, this is not applicable.

Verify RHEL 10 audit logging is enabled for the USBGuard daemon. 

Confirm the setting with the following command:

$ sudo grep AuditBackend /etc/usbguard/usbguard-daemon.conf
AuditBackend=LinuxAudit

If "AuditBackend" is not set to "LinuxAudit", this is a finding.'
  desc 'fix', 'Configure RHEL 10 USBGuard AuditBackend to use the audit system.

Add or edit the following line in "/etc/usbguard/usbguard-daemon.conf":

AuditBackend=LinuxAudit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-280965'
  tag rid: 'SV-280965r1165250_rule'
  tag stig_id: 'RHEL-10-200563'
  tag fix_id: 'F-85431r1165249_fix'
  tag cci: ['CCI-000169', 'CCI-000172']
  tag nist: ['AU-12 a', 'AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe parse_config_file('/etc/usbguard/usbguard-daemon.conf') do
    its('AuditBackend') { should cmp 'LinuxAudit' }
  end
end
