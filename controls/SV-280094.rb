control 'SV-280094' do
  title 'RHEL 10 must disable the debug-shell systemd service.'
  desc 'The debug-shell requires no authentication and provides root privileges to anyone who has physical access to the machine. While this feature is disabled by default, masking it adds an additional layer of assurance that it will not be enabled via a dependency in systemd. This also prevents attackers with physical access from trivially bypassing security on the machine through valid troubleshooting configurations and gaining root access when the system is rebooted.'
  desc 'check', 'Verify RHEL 10 is configured to mask the debug-shell systemd service with the following command:

$ sudo systemctl status debug-shell.service
o debug-shell.service
        Loaded: masked (Reason: Unit debug-shell.service is masked.)
        Active: inactive (dead)

If the "debug-shell.service" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mask the debug-shell systemd service with the following command:

$ sudo systemctl disable --now debug-shell.service
$ sudo systemctl mask --now debug-shell.service'
  impact 0.5
  tag check_id: 'C-84655r1158919_chk'
  tag severity: 'medium'
  tag gid: 'V-280094'
  tag rid: 'SV-280094r1184607_rule'
  tag stig_id: 'RHEL-10-700970'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-84560r1158920_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
