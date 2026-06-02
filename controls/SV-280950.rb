control 'SV-280950' do
  title 'RHEL 10 must not have the "gdm" package installed.'
  desc 'Unnecessary service packages must not be installed to decrease the attack surface of the system. A graphical environment is unnecessary for certain types of systems including a virtualization hypervisor.'
  desc 'check', 'Verify RHEL 10 does not have the "gdm" package installed with the following command:

$ sudo dnf list --installed gdm
Error: No matching Packages to list

If the "gdm" package is installed and the need for a GUI interface has not been documented with the information system security officer, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have the "gdm" package installed with the following command:

$ sudo dnf -y remove gdm'
  impact 0.5
  tag check_id: 'C-85511r1165203_chk'
  tag severity: 'medium'
  tag gid: 'V-280950'
  tag rid: 'SV-280950r1165205_rule'
  tag stig_id: 'RHEL-10-200080'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85416r1165204_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
