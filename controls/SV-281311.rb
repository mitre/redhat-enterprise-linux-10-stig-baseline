control 'SV-281311' do
  title 'RHEL 10 must disable the "kernel.core_pattern".'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify RHEL 10 disables storing core dumps.

Check the status of the "kernel.core_pattern" kernel parameter with the following command:

$ sudo sysctl kernel.core_pattern
kernel.core_pattern = |/bin/false

If "kernel.core_pattern" is not set to "|/bin/false", or a line is not returned and the need for core dumps is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable storing core dumps. 

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_core_pattern.conf

Add the following to the file:

kernel.core_pattern = |/bin/false

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281311'
  tag rid: 'SV-281311r1167083_rule'
  tag stig_id: 'RHEL-10-701090'
  tag fix_id: 'F-85777r1167082_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag legacy: []
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('storing_core_dumps_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    parameter = 'kernel.core_pattern'
    value = '|/bin/false'
    regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

    describe kernel_parameter(parameter) do
      its('value') { should eq value }
    end

    search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

    correct_result = search_results.any? { |line| line.match(regexp) }
    incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

    describe 'Kernel config files' do
      it "should configure '#{parameter}'" do
        expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
      end
      unless incorrect_results.nil?
        it 'should not have incorrect or conflicting setting(s) in the config files' do
          expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
        end
      end
    end
  end
end
