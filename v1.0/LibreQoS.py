# Copyright (C) 2020-2021  Robert Chacón
# This file is part of LibreQoS.
#
# LibreQoS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# LibreQoS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LibreQoS.  If not, see <http://www.gnu.org/licenses/>.
#
#            _     _ _               ___       ____  
#           | |   (_) |__  _ __ ___ / _ \  ___/ ___| 
#           | |   | | '_ \| '__/ _ \ | | |/ _ \___ \ 
#           | |___| | |_) | | |  __/ |_| | (_) |__) |
#           |_____|_|_.__/|_|  \___|\__\_\\___/____/
#                          v.1.0-stable
#
import sys
import logging
import os
import io
import json
import csv
import subprocess
from datetime import datetime
from ispConfig import (
    fqOrCAKE,
    upstreamBandwidthCapacityDownloadMbps,
    upstreamBandwidthCapacityUploadMbps,
    defaultClassCapacityDownloadMbps,
    defaultClassCapacityUploadMbps,
    tcpOverheadFactor,
    enableActualShellCommands
)
import collections


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('libreqos')
logger_shell = logger.getChild('shell')


def shell(command):
    if enableActualShellCommands:
        commands = command.split(' ')
        logger_shell.debug(command)
        proc = subprocess.Popen(commands, stdout=subprocess.PIPE)
        for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):  # or another encoding
            print(line)
    else:
        logger_shell.debug(command)


def clearPriorSettings(interfaceA, interfaceB):
    shell('tc filter delete dev ' + interfaceA)
    shell('tc filter delete dev ' + interfaceA + ' root')
    shell('tc qdisc delete dev ' + interfaceA + ' root')
    shell('tc qdisc delete dev ' + interfaceA)
    shell('tc filter delete dev ' + interfaceB)
    shell('tc filter delete dev ' + interfaceB + ' root')
    shell('tc qdisc delete dev ' + interfaceB + ' root')
    shell('tc qdisc delete dev ' + interfaceB)


def loadDevices():
    devices = []
    with open('Shaper.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            deviceID, AP, mac, hostname, ipv4, ipv6, downloadMin, uploadMin, downloadMax, uploadMax = row
            ipv4 = ipv4.strip()
            ipv6 = ipv6.strip()
            if AP == "":
                AP = "none"
            AP = AP.strip()
            thisDevice = {
                "id": deviceID,
                "mac": mac,
                "AP": AP,
                "hostname": hostname,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "downloadMin": float(round(float(downloadMin) * tcpOverheadFactor)),
                "uploadMin": float(round(float(uploadMin) * tcpOverheadFactor)),
                "downloadMax": float(round(float(downloadMax) * tcpOverheadFactor)),
                "uploadMax": float(round(float(uploadMax) * tcpOverheadFactor)),
                "qdisc": '',
            }
            devices.append(thisDevice)
    return devices


def loadSites():
    # Load Sites
    sites = []
    with open('Sites.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            siteName, download, upload = row
            siteDownloadMbps = int(download)
            siteUploadMbps = int(upload)
            sites.append((siteName, siteDownloadMbps, siteUploadMbps))
    return sites


def setupXDP(interfaceA, interfaceB):
    shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceA + ' --default --disable')
    shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceB + ' --default --disable')
    shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceA + ' --lan')
    shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceB + ' --wan')
    shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --clear')
    shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceA)
    shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceB)


def getAvailableQueueCount(interface):
    queuesAvailable = 0
    path = '/sys/class/net/' + interfaceA + '/queues/'
    directory_contents = os.listdir(path)
    logger.debug(directory_contents)
    for item in directory_contents:
        if "tx-" in str(item):
            queuesAvailable += 1

    # For VMs, must reduce queues if more than 9, for some reason
    if queuesAvailable > 9:
        command = 'grep -q ^flags.*\ hypervisor\  /proc/cpuinfo && echo "This machine is a VM"'
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).decode()
            success = True
        except subprocess.CalledProcessError as e:
            output = e.output.decode()
            success = False
        if "This machine is a VM" in output:
            queuesAvailable = 9
    return queuesAvailable


def refreshShapers():
    accessPointDownloadMbps = {}
    accessPointUploadMbps = {}

    # Load Devices
    devices = loadDevices()

    # Load sites
    sites = loadSites()

    # Sort devices into bins by AP, for scenario shapeBySite = False
    accessPointDownloadMbps['none'] = upstreamBandwidthCapacityDownloadMbps
    accessPointUploadMbps['none'] = upstreamBandwidthCapacityUploadMbps

    # Clear Prior Settings
    clearPriorSettings(interfaceA, interfaceB)

    # XDP-CPUMAP-TC
    setupXDP(interfaceA, interfaceB)

    # Find queues available
    queuesAvailable = getAvailableQueueCount(interfaceA)
    if queuesAvailable <= 1:
        raise Exception(f'Cannot perform QoS on non-multiqueue interface {interfaceA}/{interfaceB}')

    # Create MQ
    thisInterface = interfaceA
    shell('tc qdisc replace dev ' + thisInterface + ' root handle 7FFF: mq')
    for queue in range(queuesAvailable):
        shell('tc qdisc add dev ' + thisInterface + ' parent 7FFF:' + str(queue + 1) + ' handle ' + str(
            queue + 1) + ': htb default 2')
        shell('tc class add dev ' + thisInterface + ' parent ' + str(queue + 1) + ': classid ' + str(
            queue + 1) + ':1 htb rate ' + str(upstreamBandwidthCapacityDownloadMbps) + 'mbit ceil ' + str(
            upstreamBandwidthCapacityDownloadMbps) + 'mbit')
        shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':1 ' + fqOrCAKE)
        # Default class - traffic gets passed through this limiter with lower priority if not otherwise classified by the Shaper.csv
        # Only 1/4 of defaultClassCapacity is guarenteed (to prevent hitting ceiling of upstream), for the most part it serves as an "up to" ceiling.
        # Default class can use up to defaultClassCapacityDownloadMbps when that bandwidth isn't used by known hosts.
        shell('tc class add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':1 classid ' + str(
            queue + 1) + ':2 htb rate ' + str(defaultClassCapacityDownloadMbps / 4) + 'mbit ceil ' + str(
            defaultClassCapacityDownloadMbps) + 'mbit prio 5')
        shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':2 ' + fqOrCAKE)

    thisInterface = interfaceB
    shell('tc qdisc replace dev ' + thisInterface + ' root handle 7FFF: mq')
    for queue in range(queuesAvailable):
        shell('tc qdisc add dev ' + thisInterface + ' parent 7FFF:' + str(queue + 1) + ' handle ' + str(
            queue + 1) + ': htb default 2')
        shell('tc class add dev ' + thisInterface + ' parent ' + str(queue + 1) + ': classid ' + str(
            queue + 1) + ':1 htb rate ' + str(upstreamBandwidthCapacityUploadMbps) + 'mbit ceil ' + str(
            upstreamBandwidthCapacityUploadMbps) + 'mbit')
        shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':1 ' + fqOrCAKE)
        # Default class - traffic gets passed through this limiter with lower priority if not otherwise classified by the Shaper.csv.
        # Only 1/4 of defaultClassCapacity is guarenteed (to prevent hitting ceiling of upstream), for the most part it serves as an "up to" ceiling.
        # Default class can use up to defaultClassCapacityUploadMbps when that bandwidth isn't used by known hosts.
        shell('tc class add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':1 classid ' + str(
            queue + 1) + ':2 htb rate ' + str(defaultClassCapacityUploadMbps / 4) + 'mbit ceil ' + str(
            defaultClassCapacityUploadMbps) + 'mbit prio 5')
        shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue + 1) + ':2 ' + fqOrCAKE)


    currentQueueCounter = 1
    queueMinorCounterDict = {}
    # :1 and :2 are used for root and default classes, so start each counter at :3
    for queueNum in range(queuesAvailable):
        queueMinorCounterDict[queueNum + 1] = 3

        major = currentQueueCounter
        minor = queueMinorCounterDict[currentQueueCounter]
        thisAPclassID = str(currentQueueCounter) + ':' + str(minor)
        # HTB + qdisc for each AP
        # Guarentee AP gets at least 1/4 of its radio capacity, allow up to its max radio capacity when network not at peak load
        # shell('tc class add dev ' + interfaceA + ' parent ' + str(major) + ':1 classid ' + str(
        #     minor) + ' htb rate ' + str(round(thisAPdownload / 4)) + 'mbit ceil ' + str(
        #     round(thisAPdownload)) + 'mbit prio 3')
        # shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
        # shell('tc class add dev ' + interfaceB + ' parent ' + str(major) + ':1 classid ' + str(
        #     minor) + ' htb rate ' + str(round(thisAPupload / 4)) + 'mbit ceil ' + str(
        #     round(thisAPupload)) + 'mbit prio 3')
        # shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
        minor += 1
        for device in devices:
            # HTB + qdisc for each device
            shell('tc class add dev ' + interfaceA + ' parent ' + thisAPclassID + ' classid ' + str(
                minor) + ' htb rate ' + str(device['downloadMin']) + 'mbit ceil ' + str(
                device['downloadMax']) + 'mbit prio 3')
            shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
            shell('tc class add dev ' + interfaceB + ' parent ' + thisAPclassID + ' classid ' + str(
                minor) + ' htb rate ' + str(device['uploadMin']) + 'mbit ceil ' + str(
                device['uploadMax']) + 'mbit prio 3')
            shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
            if device['ipv4']:
                parentString = str(major) + ':'
                flowIDstring = str(major) + ':' + str(minor)
                shell(
                    './xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv4'] + ' --cpu ' + str(
                        currentQueueCounter - 1) + ' --classid ' + flowIDstring)
            # Once XDP-CPUMAP-TC handles IPv6, this can be added
            # if device['ipv6']:
            #	parentString = str(major) + ':'
            #	flowIDstring = str(major) + ':' + str(minor)
            #	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv6'] + ' --cpu ' + str(currentQueueCounter-1) + ' --classid ' + flowIDstring)
            device['qdisc'] = str(major) + ':' + str(minor)
            minor += 1
        queueMinorCounterDict[currentQueueCounter] = minor

        currentQueueCounter += 1
        if currentQueueCounter > queuesAvailable:
            currentQueueCounter = 1

    # Done
    currentTimeString = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    logger.info("Successful run completed on " + currentTimeString)



def usage():
    print(f'Usage: {sys.argv[0]} <command> <LAN_IFACE> <WAN_IFACE>')
    print('    commands: apply, disable')


if __name__ == '__main__':

    try:
        command = sys.argv[1]
        interfaceA = sys.argv[2]
        interfaceB = sys.argv[3]
    except IndexError:
        usage()
        sys.exit(1)

    if command == 'apply':
        refreshShapers()
    elif command == 'disable':
        clearPriorSettings(interfaceA, interfaceB)



