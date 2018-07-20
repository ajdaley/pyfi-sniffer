import os
import signal
import subprocess
import logging;

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%d/%m/%Y %I:%M:%S',
                    level="INFO")

# DEBUG (low)
# INFO
# WARNING
# ERROR
# CRITICAL (high)
#
# default is WARNING so only that and above will print
#

def get_wireless_interfaces():

    # get interfaces
    command = "iw dev"

    # attach session id to parent (shell) of subprocess
    # this makes it group leader of the process so that when
    # we send a signal to the parent, it is transmitted to all children
    sp = subprocess.Popen(command, shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)

    iw_res = filter(None, sp.communicate())

    phy_names = map(lambda iface : iface.split("\n")[0], iw_res)

    # find the interface name from the physical device name
    iface_names = map(lambda x:x[x.index("Interface ")+len("Interface "):
                      x.index("\n", x.index("Interface ")+len("Interface "))], iw_res)

    return dict(zip(phy_names, iface_names))


def get_all_interfaces():

    # unix command returning available network interfaces
    command = "lshw -class network | grep logical"

    # attach session id to parent (shell) of subprocess
    # this makes it group leader of the process so that when
    # we send a signal to the parent, it is transmitted to all children
    sp = subprocess.Popen(command, shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          preexec_fn=os.setsid())

    # map - applies function to list of inputs
    # filter - with None means that all false values are removed
    interface_list = filter(None, map(lambda s: s.strip("\n"), sp.communicate()[0].split("\n")))

    try:
        # send kill signal to all process groups
        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
    except OSError:
        logging.warning("No such process " + str(sp.pid))

    interface_list = map(lambda s: s.split("logical name: ")[-1], interface_list)

    return interface_list


def get_monitor_interfaces():
    mon_ifaces = []

    for (key, value) in get_wireless_interfaces().iteritems():
        sp = subprocess.Popen("iw " + key + " info | grep monitor", shell=True,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              preexec_fn=os.setsid())
        if "monitor" in sp.communicate()[0]:
            mon_ifaces.append(value)

        try:
            # send kill signal to all process groups
            os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
        except OSError:
            logging.debug("No such process " + str(sp.pid))

    return mon_ifaces


if __name__ == "__main__":

    ifaces = get_monitor_interfaces();
    if ifaces:
        if len(ifaces) > 1:
            logging.info("More than one interface found that supports monitor mode... using " + ifaces[0])
        else:
            logging.info("Using interface " + ifaces[0])
    else:
        logging.warning("No interfaces found. Exiting")