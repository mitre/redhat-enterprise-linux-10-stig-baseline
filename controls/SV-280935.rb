control 'SV-280935' do
  title 'RHEL 10 must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information on local disk partitions that requires at-rest protection.'
  desc 'RHEL 10 systems handling data that requires "data-at-rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Note: If there is a documented and approved reason for not having data-at-rest encryption at the operating system level, such as encryption provided by a hypervisor or a disk storage array in a virtualized environment, this requirement is not applicable.

Verify RHEL 10 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.

List all block devices in tree-like format:

$ sudo lsblk --tree
NAME                                            MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINTS
sda                                               8:0    0   64G  0 disk
+-sda1                                            8:1    0  600M  0 part  /boot/efi
+-sda2                                            8:2    0    1G  0 part  /boot
+-sda3                                            8:3    0 62.4G  0 part
  +-rhel-root                                   253:0    0   23G  0 lvm
  ¦ +-luks-9f886368-bf3e-4d17-86ed-a71dd6571bb4 253:2    0   23G  0 crypt /
  +-rhel-swap                                   253:1    0  6.4G  0 lvm   [SWAP]
  +-rhel-var_tmp                                253:3    0    3G  0 lvm
  ¦ +-luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b 253:14   0    3G  0 crypt /var/tmp
  +-rhel-var_log_audit                          253:4    0   10G  0 lvm
  ¦ +-luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502 253:9    0   10G  0 crypt /var/log/audit
  +-rhel-tmp                                    253:5    0    2G  0 lvm
  ¦ +-luks-2d7e1b45-73c4-4282-8838-15a897e0d04e 253:11   0    2G  0 crypt /tmp
  +-rhel-home                                   253:6    0   10G  0 lvm
  ¦ +-luks-ca2261ed-7b00-4b7b-84cd-8cd6d8fa4b28 253:12   0   10G  0 crypt /home
  +-rhel-var                                    253:7    0    5G  0 lvm
  ¦ +-luks-51150299-f295-4145-b8f0-ebe9c6dfd5a0 253:13   0    5G  0 crypt /var
  +-rhel-var_log                                253:8    0    3G  0 lvm
    +-luks-c651f493-9fdc-4c6e-a711-0a4f03149661 253:10   0    3G  0 crypt /var/log

Verify that the block device tree for each persistent filesystem, excluding the /boot and /boot/efi filesystems, has at least one parent block device of type "crypt" and that the encryption type is LUKS:

$ sudo cryptsetup status luks-9f886368-bf3e-4d17-86ed-a71dd6571bb4
/dev/mapper/luks-9f886368-bf3e-4d17-86ed-a71dd6571bb4 is active and is in use.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 bits
  key location: keyring
  device:  /dev/mapper/rhel-root
  sector size:  512
  offset:  32768 sectors
  size:    48201728 sectors
  mode:    read/write
  flags:   discards

If there are persistent filesystems (other than /boot or /boot/efi) whose block device trees do not have a crypt block device of type LUKS, ask the administrator to indicate how persistent filesystems are encrypted.

If there is no evidence that persistent filesystems are encrypted, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent unauthorized modification of all information at rest by using disk encryption.

Encrypting a partition in an already installed system is more difficult, because existing partitions will have to be resized and changed.

To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000405-GPOS-00184'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-280935'
  tag rid: 'SV-280935r1184775_rule'
  tag stig_id: 'RHEL-10-000510'
  tag fix_id: 'F-85401r1165159_fix'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']
  tag 'host'

  all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }

  def describe_and_skip(message)
    describe message do
      skip message
    end
  end

  # TODO: This should really have a resource

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe_and_skip('Disk Encryption and Data At Rest Implementation is handled on the Container Host')
  elsif input('data_at_rest_exempt')
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicable by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    unencrypted_drives = all_args.reject { |a|
      a.match(/\bcrypto_LUKS\b/) ||
        input('luks_exceptions').include?(a.split(':').first) ||
        a.split(':').first.match(%r{^/dev/mapper/})
    }
    describe 'All local disk partitions' do
      it 'should be encrypted with crypto_LUKS' do
        expect(unencrypted_drives).to be_empty, "The following partitions are not encrypted with crypto_LUKS:\t\n- #{unencrypted_drives.join("\t\n- ")}"
      end
    end
  end
end
