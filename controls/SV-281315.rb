control 'SV-281315' do
  title 'RHEL 10 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc "ASLR makes it more difficult for an attacker to predict the location of attack code they have introduced into a process's address space during an attempt at exploitation. Additionally, ASLR makes it more difficult for an attacker to know the location of existing code to repurpose it using return-oriented programming techniques."
  desc 'check', 'Verify RHEL 10 is implementing ASLR.

Check the status of the "kernel.randomize_va_space" kernel parameter with the following command:

$ sudo sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -rs kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf
/etc/sysctl.d/99-kernel_randomize_va_space.conf:kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', "Configure RHEL 10 to implement ASLR.

$ echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-kernel_randomize_va_space.conf

Remove any configurations that conflict with the above from the following locations: 

/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Issue the following command to make the changes take effect:

$ sudo sysctl --system"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-281315'
  tag rid: 'SV-281315r1208802_rule'
  tag stig_id: 'RHEL-10-701130'
  tag fix_id: 'F-85781r1208801_fix'
  tag cci: ['CCI-002824', 'CCI-000366']
  tag nist: ['SI-16', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.randomize_va_space'
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
