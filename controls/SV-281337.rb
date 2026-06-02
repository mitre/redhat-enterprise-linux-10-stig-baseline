control 'SV-281337' do
  title 'RHEL 10 must enable hardening for the Berkeley Packet Filter (BPF) just-in-time compiler.'
  desc 'When hardened, the extended BPF just-in-time (JIT) compiler will randomize any kernel addresses in the BPF programs and maps, and will not expose the JIT addresses in "/proc/kallsyms".'
  desc 'check', 'Verify RHEL 10 enables hardening for the BPF JIT compiler.

Check the status of the "net.core.bpf_jit_harden" parameter with the following command:

$ sudo sysctl net.core.bpf_jit_harden
net.core.bpf_jit_harden = 2

If "net.core.bpf_jit_harden" is not equal to "2" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable hardening for the BPF JIT compiler.

Create the drop-in file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-net_core-bpf_jit_harden.conf

Add the following line to the file:

net.core.bpf_jit_harden = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-281337'
  tag rid: 'SV-281337r1167161_rule'
  tag stig_id: 'RHEL-10-800050'
  tag fix_id: 'F-85803r1167160_fix'
  tag cci: ['CCI-000366', 'CCI-002824']
  tag nist: ['CM-6 b', 'SI-16']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.core.bpf_jit_harden'
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
