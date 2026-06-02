control 'SV-281335' do
  title 'RHEL 10 must disable access to the network bpf system call from nonprivileged processes.'
  desc 'Loading and accessing the packet filters programs and maps using the bpf() system call has the potential to reveal sensitive information about the kernel state.'
  desc 'check', 'Verify RHEL 10 prevents privilege escalation through the kernel by disabling access to the bpf system call.

Check the status of the "kernel.unprivileged_bpf_disabled" kernel parameter with the following command:

$ sysctl kernel.unprivileged_bpf_disabled
kernel.unprivileged_bpf_disabled = 1

If "kernel.unprivileged_bpf_disabled" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent privilege escalation through the kernel by disabling access to the bpf system call.

Create the drop-in file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_unprivileged_bpf_disabled

Add the following line to the file:

kernel.unprivileged_bpf_disabled = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-281335'
  tag rid: 'SV-281335r1167155_rule'
  tag stig_id: 'RHEL-10-800030'
  tag fix_id: 'F-85801r1167154_fix'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.unprivileged_bpf_disabled'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else
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
