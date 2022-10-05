This is Puppet manifest for installation, configuration, and control NetworkManager using keyfiles.

It is especialy designed for CentOS and its new derivates like Rocky Linux.

I have revealed and tuned a few errors connected with administration of NM through Puppet like race condition errors when I execute service and after that try to configure it using nmcli and dbus.

Now there is main nm::init class using with two boolean parameters:
  Boolean $erase_unmanaged_keyfiles = false,
  Boolean $no_auto_default = false
which ensures that the package is installed, runs service and configures man config file /etc/NetworkManager.conf.


nm::reload class
Execute take created keyfiles and starts them using nmcli. It is notified from each define.

And than there are defines to create different types of keyfiles:
nm::ifc::connection
nm::ifc::fallback
nm::ifc::bridge
nm::ifc::bridge::slave
nm::ifc::bond
nm::ifc::bond::slave
nm::ifc::vlan








