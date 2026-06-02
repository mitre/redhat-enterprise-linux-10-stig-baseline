control 'SV-281056' do
  title 'RHEL 10 must enforce root ownership of the "/etc/audit/" directory.'
  desc 'The "/etc/audit/" directory contains files that ensure the proper auditing of command execution, privilege escalation, file manipulation, and more. Protection of this directory is critical for system security.'
  desc 'check', 'Verify RHEL 10 enforces root ownership of the "/etc/audit/" directory with the following command:

$ sudo stat -c "%U %n" /etc/audit/
root /etc/audit/

If the "/etc/audit/" directory does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the "/etc/audit/" directory is owned by "root" with the following command:

$ sudo chown root /etc/audit/'
  impact 0.5
  tag check_id: 'C-85617r1165521_chk'
  tag severity: 'medium'
  tag gid: 'V-281056'
  tag rid: 'SV-281056r1165523_rule'
  tag stig_id: 'RHEL-10-400195'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-85522r1165522_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
