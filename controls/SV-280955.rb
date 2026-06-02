control 'SV-280955' do
  title 'RHEL 10 must have the "firewalld" package installed.'
  desc 'The "firewalld" package provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, that lack automated control capabilities increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganizational-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 10 functionality (e.g., Secure Shell [SSH]) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify RHEL 10 has the "firewalld" package installed.

Run the following command to determine if the "firewalld" package is installed:

Installed Packages
firewalld.noarch                             2.3.1-1.el10_0                              @rhel-10-for-x86_64-baseos-rpms

If the "firewall" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "firewalld" package installed with the following command:

$ sudo dnf -y install firewalld'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-280955'
  tag rid: 'SV-280955r1197220_rule'
  tag stig_id: 'RHEL-10-200530'
  tag fix_id: 'F-85421r1165219_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382', 'CCI-002322']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b', 'AC-17 (9)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  alternate_firewall_tool = input('alternate_firewall_tool')

  if alternate_firewall_tool == ''
    describe package('firewalld') do
      it { should be_installed }
    end
  else
    describe package(alternate_firewall_tool) do
      it { should be_installed }
    end
  end
end
