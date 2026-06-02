control 'SV-281096' do
  title 'RHEL 10 must enable the systemd-journald service.'
  desc 'In the event of a system failure, RHEL 10 must preserve any information necessary to determine cause of failure and return to operations with least disruption to system processes.'
  desc 'check', 'Verify RHEL 10 enables the systemd-journald service with the following command:

$ systemctl is-active systemd-journald
active

If the systemd-journald service is not active, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable the systemd-journald service.

To enable the systemd-journald service, run the following command:

$ sudo systemctl enable --now systemd-journald'
  impact 0.5
  tag check_id: 'C-85657r1165641_chk'
  tag severity: 'medium'
  tag gid: 'V-281096'
  tag rid: 'SV-281096r1165643_rule'
  tag stig_id: 'RHEL-10-500000'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-85562r1165642_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
