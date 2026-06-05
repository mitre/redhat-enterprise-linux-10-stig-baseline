control 'SV-281062' do
  title 'RHEL 10 must enforce mode "0640" or less permissive for the "/var/log/messages" file.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 10 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify RHEL 10 is configured so that the "/var/log/messages" file has a mode of "0640" or less permissive with the following command:

$ stat -c '%a %n' /var/log/messages
600 /var/log/messages

If "/var/log/messages" does not have a mode of "0640" or less permissive, this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that the "/var/log/messages" file has a mode of "0640" by running the following command:

$ sudo chmod 0640 /var/log/messages'
  impact 0.5
  tag check_id: 'C-85623r1165539_chk'
  tag severity: 'medium'
  tag gid: 'V-281062'
  tag rid: 'SV-281062r1165541_rule'
  tag stig_id: 'RHEL-10-400225'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-85528r1165540_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe.one do
    describe file('/var/log/messages') do
      it { should_not be_more_permissive_than('0640') }
    end
    describe file('/var/log/messages') do
      it { should_not exist }
    end
  end
end
