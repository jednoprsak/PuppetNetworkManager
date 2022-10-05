type NMMod::IP::Address::V4::CIDR = Pattern[/([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}\/([0-9]|[12][0-9]|3[0-2])(\,[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])?/]
type NMMod::DNS::IPV4 = Pattern[/(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}\;){,5}/]
type NMMod::DNS::IPV6 = Pattern[/([[:xdigit:]]{1,4}(:[[:xdigit:]]{1,4}){7}){,5}/]

class nm::init (
  Boolean $erase_unmanaged_keyfiles = false,
  Boolean $no_auto_default = false
)
{
 
 if $no_auto_default == false {
 $networkmanagerconf = @(NMCONF)
 [main]
 plugins=keyfile,ifupdown
 |NMCONF
 
 $no_auto_profiles = 'present'
 }
 elsif $no_auto_default == true {
 $networkmanagerconf = @(NMCONF)
 [main]
 plugins=keyfile,ifupdown
 no-auto-default=*
 |NMCONF

 $no_auto_profiles = 'absent'
 }

 
 package { 'NetworkManager':
    ensure => installed,
 }

 service {
    'NetworkManager.service':
      ensure => 'running',
      enable => true,
      require => [ Package['NetworkManager'], File['/etc/NetworkManager/NetworkManager.conf'] ];
 } 
 
 file {
  "/etc/NetworkManager/NetworkManager.conf":
    ensure => file,
    owner =>  'root',
    group =>  'root',
    mode   => '0600',
    notify => Service['NetworkManager.service'],
    content => $networkmanagerconf;
  "/etc/NetworkManager/system-connections/":
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    recurse => true,
    purge   => $erase_unmanaged_keyfiles,
    mode   => '0755';
 }
 
   

}

class nm::reload {
  Exec <<| tag == "nmactivate-2022b07${facts['fqdn']}" |>>
}

define nm::ifc::connection(
  Enum['absent', 'present'] $ensure = present,
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'ethernet',
  Stdlib::MAC               $mac_address = undef,
  Enum['up', 'down']        $state = 'up',
  Optional[String]          $master = undef,
  Enum['auto','dhcp','manual','disabled','link-local']        $ipv4_method = 'auto',
  Optional[NMMod::IP::Address::V4::CIDR]                      $ipv4_address = undef,
  Optional[NMMod::DNS::IPV4]          $ipv4_dns = undef,
  Optional[Boolean]         $ipv4_may_fail = true,
  Optional[Stdlib::IP::Address::V4::Nosubnet]                 $ipv4_gateway = undef,
  Enum['auto','dhcp','manual','ignore','link-local']        $ipv6_method = 'auto',
  Optional[Stdlib::IP::Address::V6::CIDR]                     $ipv6_address = undef,
  Optional[Stdlib::IP::Address::V6::Nosubnet]                 $ipv6_gateway = undef,
  Optional[NMMod::DNS::IPV6]          $ipv6_dns = undef,
  Optional[String]          $ipv6_dhcp_duid = undef,
  Variant[Integer[0, 1]]    $ipv6_addr_gen_mode = 0,
  Variant[Integer[-1, 2]]   $ipv6_privacy = 0,
  Boolean                   $ipv6_may_fail = true,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Connection[$title]

  if $master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        master => $master,
      },
      ethernet => {
        mac-address => $mac_address
      }
    }
  }
  elsif !$master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
      },
      ethernet => {
        mac-address => $mac_address
      }
    }
  }

  if ($ipv4_method == 'manual' or $ipv4_address) and $ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       gateway => $ipv4_gateway,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif ($ipv4_method == 'manual' or $ipv4_address) and !$ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'auto' or $ipv4_method == 'dhcp' {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'disabled' or ipv4_method == 'link-local' {
    $ipv4_config = {
      ipv4 => {
        method => $ipv4_method
      }
    }
  }



  if ($ipv6_method == 'manual' or $ipv6_address) and $ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        gateway => $ipv6_gateway,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif ($ipv6_method == 'manual' or $ipv6_address) and !$ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif $ipv6_dhcp_duid == undef and ($ipv6_method == 'auto' or $ipv6_method == 'dhcp' )
  {
    $ipv6_config = {
      ipv6 => {
        method => 'ignore'
      }
    }
  }
  elsif $ipv6_method == 'auto' or ipv6_method == 'dhcp'
  {
   $ipv6_config = {
      ipv6 => {
        method => $ipv6_method,
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
        dhcp-duid => $ipv6_dhcp_duid
      }
   }
  }
  elsif $ipv6_method == 'ignore' or $ipv6_method == 'link-local' {
    $ipv6_config = {
      ipv6 => {
        method => $ipv6_method
      }
    }
  }
 
  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $ipv4_config, $ipv6_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }

  if $ensure == present {
  
  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }

  }

  include nm::reload
  Nm::Ifc::Connection[$title] ~> Class['nm::reload']
}


define nm::ifc::fallback(
  Enum['absent', 'present'] $ensure = present,
  Enum['up', 'down']        $state = 'up',
  Hash                      $ifc_data_default = {},
  Hash                      $ifc_data = {}, #pozaduje tento hash
  Hash                      $ethernet_connection_files = {},
  Boolean                   $only_managed = false
)
{
  include nm::init
  Nm::Ifc::Fallback[$title] ~> Class['nm::init']
  File['/etc/NetworkManager/NetworkManager.conf'] -> Nm::Ifc::Fallback[$title]
  
  file {
    '/etc/NetworkManager/system-connections':
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      recurse => $only_managed,
      purge   => $only_managed,
      force   => $only_managed;
  }  
 
  $connections_e = deep_merge($ifc_data_default, $ifc_data)

  $connections_e.each | $connection, $params | {
    if $params['ensure'] {
      $ensure = $params['ensure']
    }
    else {
      $ensure = 'present'
    }
    $ensure_file = $ensure ? {
      'absent' => 'absent',
      default  => 'file'
    }
    
    $confilename = "/etc/NetworkManager/system-connections/${connection}.nmconnection"
    $uuid = fqdn_uuid("${facts['certname']}${connection}sPubI8dBBZgpiY9j5OwJpF")
    # fqdn uuid pocita UUID ze stringu
    $needed_params = {
      'connection' => {
        'id'          => $connection,
        'uuid'        => $uuid,
        'puppet_uuid' => 'absent',
        'type'        => 'ethernet',
        'permissions' => '',
      },
      'ethernet'   => {
        'auto-negotiate' => 'true',
      },
      'ipv4'       => {
        'method' => 'auto',
      },
      'ipv6'       => {
        'method' => 'auto',
      }
    }

    file {
      $confilename:
        ensure  => $ensure_file,
        owner   => 'root',
        group   => 'root',
        replace => false,
        backup  => false,
        mode    => '0600';
    }
    if $ensure != 'absent' {
      $params_e = deep_merge($needed_params, $params)
      $params_e.each | $section, $settings | {
        if $section != 'ensure' {
          $settings.each | $setting, $value | {
            if $value == 'absent' {
              $s_ensure = 'absent'  #setting ensure
            }
            else {
              $s_ensure = 'present'
            }
            #cast kvuli bondovanym a vlan interfacum
            if $setting =~ /^(master|parent)$/ and $value !~ /^\h{8}(-\h{4}){3}-\h{12}$/ {
              $value_e = fqdn_uuid("${facts['certname']}${value}sPubI8dBBZgpiY9j5OwJpF")
            }
            else {
              $value_e = $value
            }
            ########################################
            ini_setting {
              "nm connection/${connection}/${section}/${setting}":
                ensure            => $s_ensure,
                path              => $confilename,
                section           => $section,
                setting           => $setting,
                value             => $value_e,
                show_diff         => false,
                key_val_separator => '=',
                require           => File[$confilename];
            }
          }
        }
      }
    }
    if $ensure == present {    

    @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${connection}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File[$confilename],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }

  }

  }

  #zde můžu vložit soubory jako už hotová spojení (soubory, kter0 se jenom vloží do adresáře /etc/NetworkManager/system-connections/) 
  $ethernet_connection_files.each | $eth_file_name | {
    file {
      "/etc/NetworkManager/system-connections/${eth_file_name}":
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        replace => false,
        backup  => false,
        mode    => '0600',
        source  => "puppet:///modules/fzu/NM/keyfiles/${eth_file_name}";
    }
  } 
}

define nm::ifc::bridge(
  Enum['absent', 'present'] $ensure = present,
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'bridge',
  String                    $ifc_name = $title,
  Enum['up', 'down']        $state = 'up',
  Optional[String]          $master = undef,
                            $bridge_stp = undef,
                            $bridge_forward_delay = undef,
  Enum['auto','dhcp','manual','disabled','link-local']        $ipv4_method = 'auto',
  Optional[NMMod::IP::Address::V4::CIDR]                      $ipv4_address = undef,
  Optional[Stdlib::IP::Address::V4::Nosubnet]                 $ipv4_gateway = undef,
  Optional[NMMod::DNS::IPV4]          $ipv4_dns = undef,
  Optional[Boolean]         $ipv4_may_fail = true,
  Enum['auto','dhcp','manual','ignore','link-local']          $ipv6_method = 'auto',
  Optional[Stdlib::IP::Address::V6::CIDR]                     $ipv6_address = undef,
  Optional[Stdlib::IP::Address::V6::Nosubnet]                 $ipv6_gateway = undef,
  Optional[NMMod::DNS::IPV6]          $ipv6_dns = undef,
  Optional[String]          $ipv6_dhcp_duid = undef,
  Variant[Integer[0, 1]]    $ipv6_addr_gen_mode = 0,
  Variant[Integer[-1, 2]]   $ipv6_privacy = 0,
  Boolean                   $ipv6_may_fail = true,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Bridge[$title]

  if $master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $ifc_name,
        master => $master,
      },
      bridge => {
        stp => $bridge_stp,
        forward-delay => '2',
      }
    }
  }
  elsif !$master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $ifc_name,
      },
      bridge => {
        stp => $bridge_stp,
        forward-delay => '2',
      }
    }
  }

  if ($ipv4_method == 'manual' or $ipv4_address) and $ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       gateway => $ipv4_gateway,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif ($ipv4_method == 'manual' or $ipv4_address) and !$ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'auto' or $ipv4_method == 'dhcp' {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'disabled' or ipv4_method == 'link-local' {
    $ipv4_config = {
      ipv4 => {
        method => $ipv4_method
      }
    }
  }

  if ($ipv6_method == 'manual' or $ipv6_address) and $ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        gateway => $ipv6_gateway,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif ($ipv6_method == 'manual' or $ipv6_address) and !$ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif $ipv6_dhcp_duid == undef and ($ipv6_method == 'auto' or $ipv6_method == 'dhcp' )
  {
    $ipv6_config = {
      ipv6 => {
        method => 'ignore'
      }
    }
  }
  elsif $ipv6_method == 'auto' or ipv6_method == 'dhcp'
  {
   $ipv6_config = {
      ipv6 => {
        method => $ipv6_method,
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
        dhcp-duid => $ipv6_dhcp_duid
      }
   }
  }
  elsif $ipv6_method == 'ignore' or $ipv6_method == 'link-local' {
    $ipv6_config = {
      ipv6 => {
        method => $ipv6_method
      }
    }
  }
 
  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $ipv4_config, $ipv6_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }
  if $ensure == present {

  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }

  }

  include nm::reload
  Nm::Ifc::Bridge[$title] ~> Class['nm::reload']
}

define nm::ifc::bridge::slave(
  Enum['absent', 'present'] $ensure = present,
  Enum['up', 'down']        $state = 'up',
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'ethernet',
  String                    $master = undef,
  String                    $slave_type = 'bridge',
  Stdlib::MAC               $mac_address = undef,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Bridge::Slave[$title]

  $connection_config = {
    connection => {
      id => $id,
      uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
      type => $type,
      master => $master,
      slave-type => $slave_type
    },
    ethernet => {
      mac-address => $mac_address
    }
  }

 
  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }
  
  if $ensure == present {

  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }

  }

  include nm::reload
  Nm::Ifc::Bridge::Slave[$title] ~> Class['nm::reload']
}

define nm::ifc::bond(
  Enum['absent', 'present'] $ensure = present,
  Enum['up', 'down']        $state = 'up',
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'bond',
  String                    $ifc_name = $title,
  Optional[String]          $master = undef,
  String                    $bond_mode = 'balance-rr',
  Enum['auto','dhcp','manual','disabled','link-local']        $ipv4_method = 'auto',
  Optional[NMMod::IP::Address::V4::CIDR]                      $ipv4_address = undef,
  Optional[Stdlib::IP::Address::V4::Nosubnet]                 $ipv4_gateway = undef,
  Optional[NMMod::DNS::IPV4]          $ipv4_dns = undef,
  Optional[Boolean]         $ipv4_may_fail = true,
  Enum['auto','dhcp','manual','ignore','link-local']        $ipv6_method = 'auto',
  Optional[Stdlib::IP::Address::V6::CIDR]                     $ipv6_address = undef,
  Optional[Stdlib::IP::Address::V6::Nosubnet]                 $ipv6_gateway = undef,
  Optional[NMMod::DNS::IPV6]          $ipv6_dns = undef,
  Optional[String]          $ipv6_dhcp_duid = undef,
  Variant[Integer[0, 1]]    $ipv6_addr_gen_mode = 0,
  Variant[Integer[-1, 2]]   $ipv6_privacy = 0,
  Boolean                   $ipv6_may_fail = true,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Bond[$title]

  if $master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $ifc_name,
        master => $master,
      },
      bond => {
        mode => $bond_mode
      }
    }
  }
  elsif !$master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $ifc_name,
      },
      bond => {
        mode => $bond_mode
      }
    }
  }

  if ($ipv4_method == 'manual' or $ipv4_address) and $ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       gateway => $ipv4_gateway,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif ($ipv4_method == 'manual' or $ipv4_address) and !$ipv4_gateway {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       address => $ipv4_address,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'auto' or $ipv4_method == 'dhcp' {
    $ipv4_config = {
      ipv4 => {
       method => $ipv4_method,
       dns => $ipv4_dns,
       may-fail => $ipv4_may_fail
      }
    }
  }
  elsif $ipv4_method == 'disabled' or ipv4_method == 'link-local' {
    $ipv4_config = {
      ipv4 => {
        method => $ipv4_method
      }
    }
  }

  if ($ipv6_method == 'manual' or $ipv6_address) and $ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        gateway => $ipv6_gateway,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif ($ipv6_method == 'manual' or $ipv6_address) and !$ipv6_gateway {
    $ipv6_config = {
      ipv6 => {
        method => 'manual',
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
      }
    }
  }
  elsif $ipv6_dhcp_duid == undef and ($ipv6_method == 'auto' or $ipv6_method == 'dhcp' )
  {
    $ipv6_config = {
      ipv6 => {
        method => 'ignore'
      }
    }
  }
  elsif $ipv6_method == 'auto' or ipv6_method == 'dhcp'
  {
   $ipv6_config = {
      ipv6 => {
        method => $ipv6_method,
        address => $ipv6_address,
        addr-gen-mode => $ipv6_addr_gen_mode,
        ip6-privacy => $ipv6_privacy,
        may-fail => $ipv6_may_fail,
        dns => $ipv6_dns,
        dhcp-duid => $ipv6_dhcp_duid
      }
   }
  }
  elsif $ipv6_method == 'ignore' or $ipv6_method == 'link-local' {
    $ipv6_config = {
      ipv6 => {
        method => $ipv6_method
      }
    }
  }
 
  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $ipv4_config, $ipv6_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }

  if $ensure == present {
  
  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }
  
  }

  include nm::reload
  Nm::Ifc::Bond[$title] ~> Class['nm::reload']
}

define nm::ifc::bond::slave(
  Enum['absent', 'present'] $ensure = present,
  Enum['up', 'down']        $state = 'up',
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'ethernet',
  String                    $master = undef,
  String                    $slave_type = 'bond',
  Stdlib::MAC               $mac_address = undef,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Bond::Slave[$title]

  $connection_config = {
    connection => {
      id             => $id,
      uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
      type           => $type,
      master         => $master,
      slave-type     => $slave_type 
    },
    ethernet => {
      mac-address => $mac_address
    }
  }

  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }
  
  if $ensure == present {
  
  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }

  }

  include nm::reload
  Nm::Ifc::Bond::Slave[$title] ~> Class['nm::reload']
}

define nm::ifc::vlan(
  Enum['absent', 'present'] $ensure = present,
  String                    $id = $title, #connection name used during the start via nmcli
  String                    $type = 'vlan',
  Enum['up', 'down']        $state = 'up',
  Optional[String]          $master = undef,
  String                    $slave_type  = 'bridge',
  String                    $vlan_id = undef,
                            $vlan_flags = 1,
  String                    $vlan_parent = undef,
  Hash                      $additional_config = {}
)
{
  include nm::init
  Class['nm::init'] -> Nm::Ifc::Vlan[$title]

  if $master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $id,
        slave-type => $slave_type,
        master => $master,
      },
      vlan => {
        id => $vlan_id,
        flags => $vlan_flags,
        parent => $vlan_parent,
      },
    }
  }
  elsif !$master {
    $connection_config = {
      connection => {
        id => $id,
        uuid => fqdn_uuid("${facts['certname']}${connection}LhnwaBJRvM7epsnZTndTVmlbc${id}"),
        type => $type,
        interface-name => $id,
      },
      vlan => {
        id => $vlan_id,
        flags => $vlan_flags,
        parent => $vlan_parent,
      },
    }
  }

 
  file { 
   "/tmp/${id}.nmconnection":
      ensure    => file,
      owner     => 'root',
      group     => 'root',
      replace   => true,
      mode      => '0600',
      content   => '',
      backup    => false,
      show_diff => false;
  }
  $tempfile_settings = {
    'path'              => "/tmp/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/tmp/${id}.nmconnection"]
  }

  $keyfile_contents = deep_merge($connection_config, $ipv4_config, $ipv6_config, $additional_config)
  $keyfile_settings = {
    'path'              => "/etc/NetworkManager/system-connections/${id}.nmconnection",
    'key_val_separator' => '=',
    'require'           => File["/etc/NetworkManager/system-connections/${id}.nmconnection"]
  }
 
  create_ini_settings($keyfile_contents, $tempfile_settings)

 
  file { 
     "/etc/NetworkManager/system-connections/${id}.nmconnection":
     ensure => $ensure,
     owner  => 'root',
     group  => 'root',
     replace   => true,
     mode   => '0600',
     source => "/tmp/${id}.nmconnection",
     require => File["/tmp/${id}.nmconnection"];
  }

  if $ensure == present {
  
  @@exec { "activate ${id}":
     command => "/usr/bin/sleep 2 && /usr/bin/nmcli connection reload && /usr/bin/nmcli connection ${state} ${id}",
     provider    => 'shell',
     group => 'root',
     user => 'root',
     subscribe => File["/etc/NetworkManager/system-connections/${id}.nmconnection"],
     refreshonly => true,
     tag => "nmactivate-2022b07${facts['fqdn']}";
  }
  
  }

  include nm::reload
  Nm::Ifc::Vlan[$title] ~> Class['nm::reload']
}

