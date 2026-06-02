control 'SV-281306' do
  title 'RHEL 10 must prevent kernel profiling by nonprivileged users.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Setting the "kernel.perf_event_paranoid" kernel parameter to "2" prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify RHEL 10 is configured to prevent kernel profiling by nonprivileged users.

Check the status of the "kernel.perf_event_paranoid" kernel parameter:

$ sudo sysctl kernel.perf_event_paranoid
kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent kernel profiling by nonprivileged users.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_perf_event_paranoid.conf

Add the following to the file:

kernel.perf_event_paranoid = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-281306'
  tag rid: 'SV-281306r1167068_rule'
  tag stig_id: 'RHEL-10-701040'
  tag fix_id: 'F-85772r1167067_fix'
  tag cci: ['CCI-001090', 'CCI-001082']
  tag nist: ['SC-4', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.perf_event_paranoid'
  value = 2
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
