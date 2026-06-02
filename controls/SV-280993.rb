control 'SV-280993' do
  title 'RHEL 10 must have the "audit" package installed.'
  desc 'Without establishing what type of events occurred, along with the source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured RHEL 10 system.

'
  desc 'check', 'Verify RHEL 10 has the "audit" service package installed with the following command:

$ sudo dnf list --installed audit
Installed Packages
audit.x86_64                                           4.0.3-1.el10                                            @anaconda

If the "audit" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "audit" service package installed with the following command:

$ sudo dnf -y install audit'
  impact 0.5
  tag check_id: 'C-85554r1195380_chk'
  tag severity: 'medium'
  tag gid: 'V-280993'
  tag rid: 'SV-280993r1195381_rule'
  tag stig_id: 'RHEL-10-200660'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-85459r1165333_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000475-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-001876', 'CCI-001464', 'CCI-001487', 'CCI-001914', 'CCI-001875', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-003938', 'CCI-002884', 'CCI-000172']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-7 a', 'AU-14 (1)', 'AU-3 f', 'AU-12 (3)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b', 'AU-8 b', 'CM-5 (1) (b)', 'MA-4 (1) (a)', 'AU-12 c']
end
