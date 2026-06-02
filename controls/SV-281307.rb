control 'SV-281307' do
  title 'RHEL 10 must prevent the loading of a new kernel for later execution.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used to subvert the entire secureboot process and should be avoided at all costs, especially because it can load unsigned kernel images.'
  desc 'check', 'Verify RHEL 10 is configured to disable kernel image loading.

Check the status of the "kernel.kexec_load_disabled" kernel parameter with the following command:

$ sudo sysctl kernel.kexec_load_disabled
kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable kernel image loading.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_kexec_load_disabled.conf

Add the following to the file:

kernel.kexec_load_disabled = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-281307'
  tag rid: 'SV-281307r1184629_rule'
  tag stig_id: 'RHEL-10-701050'
  tag fix_id: 'F-85773r1184628_fix'
  tag cci: ['CCI-001749', 'CCI-000366', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-6 b', 'CM-14']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.kexec_load_disabled'
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
