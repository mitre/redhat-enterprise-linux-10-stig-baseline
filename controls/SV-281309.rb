control 'SV-281309' do
  title 'RHEL 10 must enable kernel parameters to enforce discretionary access control (DAC) on hardlinks.'
  desc 'By enabling the "fs.protected_hardlinks" kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigates vulnerabilities based on insecure file systems accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().'
  desc 'check', 'Verify RHEL 10 is configured to enable DAC on hardlinks.

Check the status of the "fs.protected_hardlinks" kernel parameter with the following command:

$ sudo sysctl fs.protected_hardlinks
fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable DAC on hardlinks.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-fs_protected_hardlinks.conf

Add the following to the file:

fs.protected_hardlinks = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124', 'SRG-OS-000324-GPOS-00125']
  tag gid: 'V-281309'
  tag rid: 'SV-281309r1184631_rule'
  tag stig_id: 'RHEL-10-701070'
  tag fix_id: 'F-85775r1184630_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'fs.protected_hardlinks'
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
