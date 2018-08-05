import os
import signal
import subprocess
import logging
from scapy.all import *

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


def printPkts(pkt):
    print pkt.show()


def put_card_monitor(iface):

    # take iface down
    logging.info("Taking iface down")
    sp = subprocess.Popen("ifconfig " + iface + " down", shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    sp.communicate()
    if sp.returncode != 0:
        logging.error("Could not take down interface")

    try:
        # send kill signal to all process groups
        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
    except OSError:
        logging.debug("No such process " + str(sp.pid))

    logging.info("Putting card into monitor")
    sp = subprocess.Popen("iwconfig " + iface + " mode monitor", shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    sp.communicate()
    if sp.returncode != 0:
        logging.error("Could not put iface into monitor mode")

    try:
        # send kill signal to all process groups
        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
    except OSError:
        logging.debug("No such process " + str(sp.pid))

    logging.info("Bringing iface up")
    sp = subprocess.Popen("ifconfig " + iface + " up", shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    sp.communicate()
    if sp.returncode != 0:
        logging.error("Could not bring interface back up")

    try:
        # send kill signal to all process groups
        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
    except OSError:
        logging.debug("No such process " + str(sp.pid))

    logging.info("Checking to see if in monitor")
    sp = subprocess.Popen("iwconfig " + iface, shell=True,
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if "Monitor" in sp.communicate()[0]:
        monitor = True
    else:
        monitor = False

    try:
        # send kill signal to all process groups
        os.killpg(os.getpgid(sp.pid), signal.SIGTERM)
    except OSError:
        logging.debug("No such process " + str(sp.pid))

    return monitor


if __name__ == "__main__":

    ifaces = get_monitor_interfaces();
    if ifaces:
        if len(ifaces) > 1:
            logging.info("More than one interface found that supports monitor mode... using " + ifaces[0])
        else:
            logging.info("Using interface " + ifaces[0])

    else:
        logging.warning("No interfaces found. Exiting")
        exit(0)

    if put_card_monitor(ifaces[0]):
        #sniff(iface="wlxf4f26d0d7431", prn=printPkts,store=0)
        sniff(iface="wlxf4f26d0d7431", prn=printPkts, store=0, count=1)
    else:
        logging.error("Card not in monitor mode")




