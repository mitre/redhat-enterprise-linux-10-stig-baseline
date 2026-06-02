control 'SV-281003' do
  title 'RHEL 10 must have the "openssh-clients" package installed.'
  desc 'This package includes utilities to make encrypted connections and transfer files securely to Secure Shell (SSH) servers.'
  desc 'check', 'Verify RHEL 10 has the "openssh-clients" package installed with the following command:

$ sudo dnf list --installed openssh-clients
Installed Packages
openssh-clients.x86_64                                     9.9p1-7.el10_0                                      @anaconda

If the "openssh-clients" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "openssh-clients" package installed with the following command:

$ sudo dnf -y install openssh-clients'
  impact 0.5
  tag check_id: 'C-85564r1195392_chk'
  tag severity: 'medium'
  tag gid: 'V-281003'
  tag rid: 'SV-281003r1195393_rule'
  tag stig_id: 'RHEL-10-200722'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85469r1165363_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('openssh-clients') do
    it { should be_installed }
  end
end
