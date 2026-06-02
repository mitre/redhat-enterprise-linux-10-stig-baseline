control 'SV-281316' do
  title 'RHEL 10 must restrict usage of ptrace to descendant processes.'
  desc 'Unrestricted usage of ptrace allows compromised binaries to run ptrace on other processes of the user. The attacker can then steal sensitive information from the target processes (e.g., SSH sessions, web browser, etc.) without any additional assistance from the user (i.e., without resorting to phishing).'
  desc 'check', 'Verify RHEL 10 restricts the usage of ptrace to descendant processes.

Check the status of the "kernel.yama.ptrace_scope" kernel parameter with the following command:

$ sysctl kernel.yama.ptrace_scope
kernel.yama.ptrace_scope = 1

If the network parameter "kernel.yama.ptrace_scope" is not equal to "1", or nothing is returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to restrict the usage of ptrace to descendant processes.

Create the drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_yama.ptrace_scope.conf

Add the following line to the file:

kernel.yama.ptrace_scope = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85877r1167096_chk'
  tag severity: 'medium'
  tag gid: 'V-281316'
  tag rid: 'SV-281316r1167098_rule'
  tag stig_id: 'RHEL-10-701140'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-85782r1167097_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.yama.ptrace_scope'
  value = 1
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
