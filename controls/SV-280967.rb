control 'SV-280967' do
  title 'RHEL 10 must have the "policycoreutils-python-utils" package installed.'
  desc 'The "policycoreutils-python-utils" package is required to operate and manage an SELinux environment and its policies. It provides utilities such as "semanage", "audit2allow", "audit2why", "chcat", and "sandbox".'
  desc 'check', 'Verify RHEL 10 has the "policycoreutils-python-utils" service package installed with the following command:

$ sudo dnf list --installed policycoreutils-python-utils
Installed Packages
policycoreutils-python-utils.noarch                                3.8-1.el10                                 @AppStream

If the "policycoreutils-python-utils" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "policycoreutils-python-utils" service package installed with the following command:

$ sudo dnf -y install policycoreutils-python-utils'
  impact 0.5
  tag check_id: 'C-85528r1195353_chk'
  tag severity: 'medium'
  tag gid: 'V-280967'
  tag rid: 'SV-280967r1195354_rule'
  tag stig_id: 'RHEL-10-200580'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85433r1165255_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('policycoreutils-python-utils') do
    it { should be_installed }
  end
end
