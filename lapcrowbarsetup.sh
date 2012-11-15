#!/bin/sh
# based on https://github.com/SUSE/cloud/wiki/SUSE-Cloud-Installation-Manual
test $(uname -m) = x86_64 || echo "ERROR: need 64bit"
#resize2fs /dev/vda2

cloud=${1:-d2}
nodenumber=${nodenumber:-2}

case $cloud in
	d1)
		net=10.122.178
		net_storage=179
		net_public=177
		net_fixed=176
		vlan_storage=568
		vlan_public=567
		vlan_fixed=566
	;;
	d2)
		net=10.122.186
		net_storage=187
		net_public=185
		net_fixed=184
		vlan_storage=581
		vlan_public=580
		vlan_fixed=569
	;;
	p)
		net=10.122.169
		net_storage=170
		net_public=168
		net_fixed=160
		vlan_storage=565
		vlan_public=564
		vlan_fixed=563
	;;
	virtual)
		net=192.168.124
	;;
	*)
		echo "Unknown Cloud"
		exit 1
	;;
esac

function intercept()
{
  if [ -n "$shell" ] ; then
    echo "Now starting bash for manual intervention..."
    echo "When ready exit this shell to continue with $1"
    bash
  fi
}


if [ -n "$preparecrowbar" ] ; then

echo configure static IP and absolute + resolvable hostname admin.cloud.selab.net gw:$net.1
cat > /etc/sysconfig/network/ifcfg-eth0 <<EOF
NAME='eth0'
STARTMODE='auto'
BOOTPROTO='static'
IPADDR='$net.10'
NETMASK='255.255.255.0'
BROADCAST='$net.255'
EOF

echo "default $net.1 - -" > /etc/sysconfig/network/routes
echo "admin.cloud.selab.net" > /etc/HOSTNAME

/bin/hostname `cat /etc/HOSTNAME`

# these vars are used by rabbitmq
export HOSTNAME=`cat /etc/HOSTNAME`
export HOST=$HOSTNAME

#Delete last line of /etc/hosts incase it has info there already and then set it up correctly.
grep -q "$net.*admin" /etc/hosts || head -n -1 /etc/hosts > /etc/hosts.new ; mv /etc/hosts.new /etc/hosts

grep -q "$net.*admin" /etc/hosts || echo $net.10 admin.cloud.selab.net admin >> /etc/hosts

#Setup /etc/resolv.conf correctly
head -n -2 /etc/resolv.conf > /etc/resolv.conf.new ; mv /etc/resolv.conf.new /etc/resolv.conf

echo search cloud.selab.net >> /etc/resolv.conf
echo nameserver $net.10 >> /etc/resolv.conf

rcnetwork restart

/bin/hostname -f # make sure it is a FQDN

ping -c 1 `/bin/hostname -f`

mkdir -p /srv/tftpboot/repos/
mkdir -p /srv/tftpboot/suse-11.2/install

mount /dev/vdb1 /srv/tftpboot/repos

echo "/dev/vdb1 /srv/tftpboot/repos   ext3    defaults  1 1" >> /etc/fstab

# copy directory to the correct one used
rsync -av /srv/tftpboot/repos/suse-11.2/install/ /srv/tftpboot/suse-11.2/install/

# add repositories 
zypper ar /srv/tftpboot/suse-11.2/install/ SLES-11-SP2
zypper ar /srv/tftpboot/repos/SLES11-SP1-Updates/ SLES11-SP1-Updates
zypper ar /srv/tftpboot/repos/SLES11-SP1-Pool/ SLES11-SP1-Pool
zypper ar /srv/tftpboot/repos/SLES11-SP2-Core/ SLES11-SP2-Core
zypper ar /srv/tftpboot/repos/SLES11-SP2-Updates/ SLES11-SP2-Updates

# refresh repositories
zypper ref

# Install dhcp-server and tftp as this sometimes causes problems if you don't.
# zypper -n in dhcp-server tftp 

# Update the system with the latest patches
# skipping the update due to a bug causing dhclient discovery loop.
zypper -n up 

# Reboot to apply the newest kernel
init 6
fi

if [ -n "$installcrowbar" ] ; then

mount -o loop,ro -t iso9660 $(ls /tmp/SUSE-CLOUD-*.iso|tail -1) /mnt

#cleanup directory first 
rm -rf /srv/tftpboot/repos/Cloud/*

rsync -avP  /mnt/ /srv/tftpboot/repos/Cloud/ ; umount /mnt
if [ ! -e "/srv/tftpboot/repos/Cloud/media.1" ] ; then
	echo "We do not have cloud install media - giving up"
	exit 35
fi

# Add SUSE Cloud Repositories
zypper ar /srv/tftpboot/repos/Cloud SLE-Cloud
zypper ar /srv/tftpboot/repos/SUSE-Cloud-1.0-Pool SUSE-Cloud-1.0-Pool
zypper ar /srv/tftpboot/repos/SUSE-Cloud-1.0-Updates SUSE-Cloud-1.0-Updates

# refresh repositories
zypper ref

if [ -e "/srv/tftpboot/repos/Cloud/media.1" ] ; then
  zypper --no-gpg-checks -n in -t pattern cloud_admin
  ret=$?
fi
if [ $ret = 0 ] ; then
  echo "The cloud admin successfully installed."
  echo ".... continuing"
else
  echo "Error: zypper returned with exit code $? when installing cloud admin"
  exit 86
fi

if [ ! -e "/srv/tftpboot/repos/suse-11.2/install/media.1/" ] ; then
	echo "We do not have SLES install media - giving up"
	exit 34
fi

# Adapt a Bastion network to get access to an external network.
#
#netfiles="/opt/dell/barclamps/network/chef/data_bags/crowbar/bc-template-network.json /opt/dell/chef/data_bags/crowbar/bc-template-network.json"
#if [ $cloud != virtual ] ; then
#	sed -i.netbak -e "s/192.168.124/$net/g" \
#              -e "s/192.168.125/10.122.$net_storage/g" \
#              -e "s/192.168.123/10.122.$net_fixed/g" \
#              -e "s/192.168.122/10.122.$net_public/g" \
#              -e "s/200/$vlan_storage/g" \
#              -e "s/300/$vlan_public/g" \
#              -e "s/500/$vlan_fixed/g" \
#		$netfiles
#fi
#if [ $cloud = p ] ; then
	# production cloud has a /21 network
#	perl -i.perlbak -pe 'if(m/255.255.255.0/){$n++} if($n==3){s/255.255.255.0/255.255.248.0/}' $netfiles
#fi

#+bmc router
#fix autoyast xml.erb update channels
#if [ ! -d "/srv/tftpboot/repos/SLES11-SP2-Updates/repodata" ] ; then
#	sed -i.bak -e 's#<media_url>http://<%= @admin_node_ip %>:8091/repos/SLES11-SP\(.\)-Updates/</media_url>#<media_url>http://euklid.suse.de/mirror/SuSE/zypp-patches.suse.de/x86_64/update/SLE-SERVER/11-SP\1/</media_url>#'\
#    -e "s/<domain>[^<]*</<domain>cloud.selab.net</" \
#    /opt/dell/barclamps/provisioner/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb /opt/dell/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb
#fi
#if [ ! -d "/srv/tftpboot/repos/SLES11-SP2-Core/repodata" ] ; then
#	sed -i.bak2 -e 's#<media_url>http://<%= @admin_node_ip %>:8091/repos/SLES11-SP1-Pool/#<media_url>http://euklid.suse.de/mirror/SuSE/zypp-patches.suse.de/x86_64/update/SLE-SERVER/11-SP1-POOL/#' -e 's#/repos/SLES11-SP2-Core/#/suse-11.2/install/#' /opt/dell/barclamps/provisioner/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb /opt/dell/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb
#fi

# to allow integration into external DNS:
#f=/opt/dell/chef/cookbooks/bind9/templates/default/named.conf.erb
#grep -q allow-transfer $f || sed -i -e "s#options {#&\n\tallow-transfer { 10.0.0.0/8; };#" $f

#sed -i -e "s#<\(partitions.*\)/>#<\1><partition><mount>swap</mount><size>auto</size></partition><partition><mount>/</mount><size>max</size><fstopt>data=writeback,barrier=0,noatime</fstopt></partition></partitions>#" /opt/dell/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb

# workaround for performance bug (bnc#770083)
sed -i -e "s#<\(partitions.*\)/>#<\1><partition><mount>swap</mount><size>auto</size></partition><partition><mount>/</mount><size>max</size><fstopt>data=writeback,barrier=0,noatime</fstopt></partition></partitions>#" /opt/dell/chef/cookbooks/provisioner/templates/default/autoyast.xml.erb

# Setup password hash for compute nodes
sed -i -e 's/\(rootpw_hash.*\)""/\1"$2y$10$J9Iqo8B91wYb9JqA1dKAruoVze.4KNtfOT20k2xsm.98DRewm9yZe"/' /opt/dell/chef/cookbooks/provisioner/recipes/setup_base_images.rb

#knife cookbook upload -o /opt/dell/chef/cookbooks/ provisioner

#intercept "install-chef-suse.sh"

rm -f /tmp/chef-ready

# run in screen to not lose session in the middle when network is reconfigured:
zypper -n in screen

screen -d -m -L /bin/bash -c 'if [ -e /opt/dell/bin/install-chef-suse.sh ] ; then /opt/dell/bin/install-chef-suse.sh ; fi ; touch /tmp/chef-ready'
n=300
while [ $n -gt 0 ] && [ ! -e /tmp/chef-ready ] ; do
	n=$(expr $n - 1)
	sleep 5;
	echo -n .
done
if [ $n = 0 ] ; then
	echo "timed out waiting for chef-ready"
	exit 83
fi

. /etc/profile.d/crowbar.sh

sleep 100
if ! curl -s http://localhost:3000 > /dev/null ; then
	tail -30 /root/screenlog.0
	echo "crowbar self-test failed"
	exit 84
fi

# Correct environment variables must be set in order for this to work properly
# Consider sourcing /etc/profile.d/crowbar.sh
if ! /opt/dell/bin/crowbar machines list | grep -q admin.cloud.selab.net ; then
	tail -30 /root/screenlog.0
	echo "crowbar 2nd self-test failed"
	exit 85
fi

if ! (rcxinetd status && rcdhcpd status) ; then
   echo "Error: provisioner failed to configure all needed services!"
   echo "Please fix manually."
   exit 67
fi

fi
# -n "$installcrowbar"

if [ -n "$allocate" ] ; then

chef-client

if [ $cloud != virtual ] ; then
	for i in 3 4 5 6 ; do
	  for pw in root crowbar ; do
		  (ipmitool -H "$net.16$i" -U root -P $pw lan set 1 defgw ipaddr "$net.1"
		  ipmitool -H "$net.16$i" -U root -P $pw power reset) &
	  done
	done
	wait
fi

echo "Waiting for nodes to come up..."
while ! crowbar machines list | grep ^d ; do sleep 10 ; done
echo "Found one node"
while test $(crowbar machines list | grep ^d|wc -l) -lt $nodenumber ; do sleep 10 ; done
echo "Sleeping 50 more seconds..."
sleep 50
for m in `crowbar machines list | grep ^d` ; do
	crowbar machines allocate "$m"
done

fi

function waitnodes()
{
  n=800
  mode=$1
  proposal=$2
  case $mode in
    nodes)
      echo -n "Waiting for nodes to get ready: "
      for i in `crowbar machines list | grep ^d` ; do
        machinestatus=''
        while test $n -gt 0 && ! test "x$machinestatus" = "xready" ; do
          machinestatus=`crowbar machines show $i | ruby -e "require 'rubygems';require 'json';puts JSON.parse(STDIN.read)['state']"`
          if test "x$machinestatus" = "xfailed" ; then
            echo "Error: machine status is failed. Exiting"
            exit 39
          fi
          sleep 5
          n=$((n-1))
          echo -n "."
        done
        n=500 ; while test $n -gt 0 && ! netcat -z $i 22 ; do
          sleep 1
          n=$(($n - 1))
          echo -n "."
        done
        echo "node $i ready"
      done
      ;;
    proposal)
      echo -n "Waiting for proposal to get successful: "
      proposalstatus=''
      while test $n -gt 0 && ! test "x$proposalstatus" = "xsuccess" ; do
        proposalstatus=`crowbar $proposal proposal show default | ruby -e "require 'rubygems';require 'json';puts JSON.parse(STDIN.read)['deployment']['$proposal']['crowbar-status']"`
        if test "x$proposalstatus" = "xfailed" ; then
          echo "Error: proposal failed. Exiting."
          exit 40
        fi
        sleep 5
        n=$((n-1))
        echo -n "."
      done
      echo "proposal $proposal successful"
      ;;
    default)
      echo "Error: waitnodes was called with wrong parameters"
      exit 72
      ;;
  esac

  if [ $n == 0 ] ; then
    echo "Error: Waiting timed out. Exiting."
    exit 74
  fi
}

if [ -n "$proposal" ] ; then
waitnodes nodes
for service in database postgresql keystone glance nova nova_dashboard ; do
  [ "$service" = "postgresql" ] && continue
  crowbar "$service" proposal create default
  crowbar "$service" proposal commit default
  waitnodes proposal $service
  sleep 10
  ret=$?
  echo "exitcode: $ret"
  if [ $ret != 0 ] ; then
    echo "Error: commiting the crowbar proposal for '$service' failed ($ret)."
    exit 73
  fi
done
fi

if [ -n "$testsetup" ] ; then
	novacontroller=`crowbar nova proposal show default | ruby -e "require 'rubygems';require 'json';puts JSON.parse(STDIN.read)['deployment']['nova']['elements']['nova-multi-controller']"`
	if [ -z "$novacontroller" ] || ! ssh $novacontroller true ; then
		echo "no nova contoller - something went wrong"
		exit 62
	fi
	echo "openstack nova contoller: $novacontroller"
	ssh $novacontroller '
		. .openrc
		curl -s w3.suse.de/~bwiedemann/cloud/defaultsuseusers.pl | perl
		nova list
		glance image-list
	        glance image-list|grep -q SP2-64 || glance image-create --name=SP2-64 --is-public=True --disk-format=qcow2 --container-format=bare --copy-from http://clouddata.cloud.suse.de/images/SP2-64up.qcow2
        nova delete testvm # cleanup earlier run # cleanup
		nova keypair-add --pub_key /root/.ssh/id_rsa.pub testkey
		nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0
		nova secgroup-add-rule default tcp 1 65535 0.0.0.0/0
		nova secgroup-add-rule default udp 1 65535 0.0.0.0/0
		nova boot --image SP2-64 --flavor 1 --key_name testkey testvm | tee boot.out
		instanceid=`perl -ne "m/ id [ |]*([0-9a-f-]+)/ && print \\$1" boot.out`
		sleep 30
		vmip=`nova show $instanceid | perl -ne "m/ nova_fixed.network [ |]*([0-9.]+)/ && print \\$1"`
		echo "VM IP address: $vmip"
        if [ -z "$vmip" ] ; then
          echo "Error: VM IP is empty. Exiting"
          exit 38
        fi
		n=1000 ; while test $n -gt 0 && ! ping -q -c 1 -w 1 $vmip >/dev/null ; do
		  n=$(expr $n - 1)
		  echo -n .
		done
		if [ $n = 0 ] ; then
			echo testvm boot or net failed
			exit 94
		fi
        echo -n "Waiting for the VM to come up: "
        n=500 ; while test $n -gt 0 && ! netcat -z $vmip 22 ; do
          sleep 1
          n=$(($n - 1))
          echo -n "."
        done
        if [ $n = 0 ] ; then
          echo "VM not accessible in reasonable time, exiting."
          exit 96
        fi
        WAITSSH=200
        echo "Waiting $WAITSSH seconds for the SSH keys to be copied over"
        sleep $WAITSSH
		if ! ssh $vmip curl www3.zq1.de/test ; then
			echo could not reach internet
			exit 95
		fi
		ssh $vmip modprobe acpiphp
		nova volume-create 1 ; sleep 2
		nova volume-list
		lvscan | grep .
		volumecreateret=$?
		nova volume-attach $instanceid 1 /dev/vdb
		sleep 15
		ssh $vmip fdisk -l /dev/vdb | grep 1073741824
		volumeattachret=$?
		nova floating-ip-create | tee floating-ip-create.out
		floatingip=$(perl -ne "if(/192\.168\.\d+\.\d+/){print \$&}" floating-ip-create.out)
		nova add-floating-ip $instanceid $floatingip # insufficient permissions
		test $volumecreateret = 0 -a $volumeattachret = 0
	'
	ret=$?
	echo ret:$ret
	exit $ret
fi


#BMCs at 10.122.178.163-6 #node 6-9
#BMCs at 10.122.$net.163-4 #node 11-12

# undo propsal create+commit
if false; then
for service in nova_dashboard nova glance keystone postgresql database ; do
        crowbar "$service" proposal delete default
        crowbar "$service" delete default
done
fi
