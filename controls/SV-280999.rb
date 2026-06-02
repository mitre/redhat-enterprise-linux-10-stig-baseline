control 'SV-280999' do
  title 'RHEL 10 must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay to send spam or for other unauthorized activity.'
  desc 'check', 'Note: If postfix is not installed, this is not applicable.

Verify RHEL 10 is configured to prevent unrestricted mail relaying with the following command:

$ postconf -n smtpd_client_restrictions
smtpd_client_restrictions = permit_mynetworks,reject

If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", and the additional entries have not been documented with the information system security officer, this is a finding.'
  desc 'fix', "Configure RHEL 10 so that the postfix configuration file restricts client connections to the local network with the following command:

$ sudo postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-280999'
  tag rid: 'SV-280999r1165352_rule'
  tag stig_id: 'RHEL-10-200692'
  tag fix_id: 'F-85465r1165351_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'
  tag 'container'

  if package('postfix').installed?
    describe command('postconf -n smtpd_client_restrictions') do
      its('stdout.strip') {
        should match(/^smtpd_client_restrictions\s+=\s+(permit_mynetworks|reject)($|(,\s*(permit_mynetworks|reject)\s*$))/i)
      }
    end
  else
    impact 0.0
    describe 'The `postfix` package is not installed' do
      skip 'The `postfix` package is not installed; this control is Not Applicable'
    end
  end
end
