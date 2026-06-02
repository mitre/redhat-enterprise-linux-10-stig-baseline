control 'SV-281322' do
  title 'RHEL 10 must disable the kdump service.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition. Unless the system is used for kernel development or testing, there is little need to run the kdump service.'
  desc 'check', 'Verify RHEL 10 disables the kdump service in system boot configuration with the following command:

$ sudo systemctl is-enabled  kdump
masked

Verify the kdump service is not active (i.e., not running) through current runtime configuration with the following command:

$ sudo systemctl is-active kdump
failed

Verify the kdump service is masked with the following command:

$ sudo systemctl show  kdump  | grep "LoadState\\|UnitFileState"
LoadState=masked
UnitFileState=masked

If the "kdump" service is loaded or active and is not masked, this is a finding.'
  desc 'fix', "Configure RHEL 10 to disable and mask the kdump service.

To disable the kdump service, run the following command:

$ sudo systemctl disable --now kdump
Removed '/etc/systemd/system/multi-user.target.wants/kdump.service'.

To mask the kdump service, run the following command:

$ sudo systemctl mask --now kdump
Created symlink '/etc/systemd/system/kdump.service' ? '/dev/null'."
  impact 0.5
  tag check_id: 'C-85883r1167114_chk'
  tag severity: 'medium'
  tag gid: 'V-281322'
  tag rid: 'SV-281322r1167116_rule'
  tag stig_id: 'RHEL-10-701200'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-85788r1167115_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
