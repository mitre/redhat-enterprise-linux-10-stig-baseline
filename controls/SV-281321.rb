control 'SV-281321' do
  title 'RHEL 10 must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc %q(ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions, such as the stack and heap, higher than this address, the hardware prevents execution in that address range. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware.

Checking "dmesg" will return a false-positive if the system has generated enough kernel messages that the "(Execute Disable) protection: active" line is no longer present in the output from "dmesg(1)". A better way to ensure that ExecShield is enabled is to first ensure all processors support the NX feature, and then to check that "noexec" was not passed to the kernel command line.)
  desc 'check', "Verify RHEL 10 enables ExecShield.

Run the following command:

$ sudo grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)'

If any output is returned, this is a finding.

Run the following command:

$ sudo grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])'

If any output is returned, this is a finding."
  desc 'fix', 'Configure RHEL 10 to enable ExecShield.

If "/proc/cpuinfo" shows that one or more processors do not enable ExecShield (lack the "nx" feature flag), verify the NX/XD feature is not disabled in the BIOS or UEFI. If it is disabled, enable it.

If the "noexec" option is present on the kernel command line, update the GRUB 2 bootloader configuration to remove it by running the following command:

$ sudo grubby --update-kernel=ALL --remove-args=noexec'
  impact 0.5
  tag check_id: 'C-85882r1167111_chk'
  tag severity: 'medium'
  tag gid: 'V-281321'
  tag rid: 'SV-281321r1167113_rule'
  tag stig_id: 'RHEL-10-701190'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-85787r1167112_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
