control 'SV-281302' do
  title 'RHEL 10 must clear the page allocator to prevent use-after-free attacks.'
  desc 'Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. It also prevents data leakage and detection of corrupted memory.'
  desc 'check', %q(Verify RHEL 10 is configured so that the current GRUB 2 configuration enables page poisoning to mitigate use-after-free vulnerabilities.

Check that the current GRUB 2 configuration has page poisoning enabled with the following command:

$ sudo grubby --info=ALL | grep args | grep -v 'page_poison=1'

If any output is returned, this is a finding.

Check that page poisoning is enabled by default to persist in kernel updates with the following command:

$ sudo grep page_poison /etc/default/grub
GRUB_CMDLINE_LINUX="page_poison=1"

If "page_poison" is not set to "1", is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to enable page poisoning with the following commands:

$ sudo grubby --update-kernel=ALL --args="page_poison=1"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-281302'
  tag rid: 'SV-281302r1167056_rule'
  tag stig_id: 'RHEL-10-701000'
  tag fix_id: 'F-85768r1167055_fix'
  tag cci: ['CCI-001084', 'CCI-000366']
  tag nist: ['SC-3', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /page_poison\s*=\s*1/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
