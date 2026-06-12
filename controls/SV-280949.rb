control 'SV-280949' do
  title 'RHEL 10 must not have the "tftp" package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities are often overlooked and therefore, may remain unsecure. They increase the risk to the platform by providing additional attack vectors.

If Trivial File Transfer Protocol (TFTP) is required for operational support (such as transmission of router configurations), its use must be documented with the information system security manager, restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify RHEL 10 does not have the "tftp" package installed with the following command:

$ sudo dnf list --installed tftp
Error: No matching Packages to list

If the "tftp" package is installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have the "tftp" package installed with the following command:

$ sudo dnf -y remove tftp'
  impact 0.7
  tag check_id: 'C-85510r1165200_chk'
  tag severity: 'high'
  tag gid: 'V-280949'
  tag rid: 'SV-280949r1195338_rule'
  tag stig_id: 'RHEL-10-200070'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-85415r1165201_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  if input('tftp_required')
    describe package('tftp') do
      it { should be_installed }
    end
  else
    describe package('tftp') do
      it { should_not be_installed }
    end
  end
end
