control 'SV-281293' do
  title 'RHEL 10 must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc "ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware."
  desc 'check', "Verify RHEL 10 implements nonexecutable data to protect its memory from unauthorized code execution.

Run the following command:

$ sudo grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)'

If any output is returned, this is a finding.

Run the following command:

$ sudo grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])'

If any output is returned, this is a finding."
  desc 'fix', 'Configure RHEL 10 to implement nonexecutable data to protect its memory from unauthorized code execution.

Update the GRUB 2 bootloader configuration.

Run the following command:

$ sudo grubby --update-kernel=ALL --remove-args=noexec'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-281293'
  tag rid: 'SV-281293r1166831_rule'
  tag stig_id: 'RHEL-10-700900'
  tag fix_id: 'F-85759r1166830_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  grep_output = command("grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)'").stdout.strip
  grubby_output = command("grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])'").stdout.strip

  describe 'ExecShield' do
    it 'is enabled on 64-bit RHEL 9 systems' do
      expect(grep_output).to be_empty
      expect(grubby_output).to be_empty
    end
  end
end
