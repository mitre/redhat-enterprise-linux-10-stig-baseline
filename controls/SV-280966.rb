control 'SV-280966' do
  title 'RHEL 10 must have the "policycoreutils" package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

The "policycoreutils" package contains the policy core utilities that are required for basic operation of an SELinux-enabled system. These utilities include "load_policy" to load SELinux policies, "setfile" to label filesystems, "newrole" to switch roles, and "run_init" to run "/etc/init.d" scripts in the proper context.'
  desc 'check', 'Verify RHEL 10 has the "policycoreutils" package installed with the following command:

$ sudo dnf list --installed policycoreutils
Installed Packages
policycoreutils.x86_64                                       3.8-1.el10                                        @anaconda

If the "policycoreutils" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "policycoreutils" package installed with the following command:

$ sudo dnf -y install policycoreutils'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-280966'
  tag rid: 'SV-280966r1195352_rule'
  tag stig_id: 'RHEL-10-200570'
  tag fix_id: 'F-85432r1165252_fix'
  tag cci: ['CCI-001084', 'CCI-000366']
  tag nist: ['SC-3', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  describe package('policycoreutils') do
    it { should be_installed }
  end
end
