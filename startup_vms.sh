#!/bin/sh
#chkconfig: 2345 40 60
#description: VirtualBox


start()
{

echo -n "Starting VM01"
/usr/bin/VBoxManage startvm "VM01" --type headless

echo -n "Starting VM02"
/usr/bin/VBoxManage startvm "VM02" --type headless

}

stop()
{

echo -n "Saving VM VM01 State..."
/usr/bin/VBoxManage controlvm "VM01" savestate

echo -n "Saving VM VM02 State..."
/usr/bin/VBoxManage controlvm "VM02" savestate

}


case "$1" in
  start)
        start
   ;;
  stop)
          stop
   ;;
  restart|reload)
        stop
   start
   ;;
  *)
        echo $"Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac

exit 0


