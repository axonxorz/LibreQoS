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
    interfaceA,
    interfaceB,
    shapeBySite,
    enableActualShellCommands,
    runShellCommandsAsSudo
)
import collections

def shell(command):
	if enableActualShellCommands:
		if runShellCommandsAsSudo:
			command = 'sudo ' + command
		commands = command.split(' ')
		print(command)
		proc = subprocess.Popen(commands, stdout=subprocess.PIPE)
		for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):  # or another encoding
			print(line)
	else:
		print(command)

def clearPriorSettings(interfaceA, interfaceB):
	shell('tc filter delete dev ' + interfaceA)
	shell('tc filter delete dev ' + interfaceA + ' root')
	shell('tc qdisc delete dev ' + interfaceA + ' root')
	shell('tc qdisc delete dev ' + interfaceA)
	shell('tc filter delete dev ' + interfaceB)
	shell('tc filter delete dev ' + interfaceB + ' root')
	shell('tc qdisc delete dev ' + interfaceB + ' root')
	shell('tc qdisc delete dev ' + interfaceB)
	if runShellCommandsAsSudo:
		clearMemoryCache()

def refreshShapers():
	tcpOverheadFactor = 1.09
	accessPointDownloadMbps = {}
	accessPointUploadMbps = {}
	
	# Load Devices
	devices = []
	with open('Shaper.csv') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		next(csv_reader)
		for row in csv_reader:
			deviceID, AP, mac, hostname,ipv4, ipv6, downloadMin, uploadMin, downloadMax, uploadMax = row
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
			  "downloadMin": round(int(downloadMin)*tcpOverheadFactor),
			  "uploadMin": round(int(uploadMin)*tcpOverheadFactor),
			  "downloadMax": round(int(downloadMax)*tcpOverheadFactor),
			  "uploadMax": round(int(uploadMax)*tcpOverheadFactor),
			  "qdisc": '',
			}
			devices.append(thisDevice)			
	
	# Load Access Points
	accessPoints = []
	accessPointNamesOnly = []
	with open('AccessPoints.csv') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		next(csv_reader)
		for row in csv_reader:
			APname, apDownload, apUpload, parentSite = row
			accessPointDownloadMbps[AP] = int(apDownload)*tcpOverheadFactor
			accessPointUploadMbps[AP] = int(apUpload)*tcpOverheadFactor
			accessPointNamesOnly.append(APname)
			apDownload = round(int(apDownload)*tcpOverheadFactor)
			apUpload = round(int(apUpload)*tcpOverheadFactor)
			devicesForThisAP = []
			for device in devices:
				if APname == device['AP']:
					devicesForThisAP.append(device)
			accessPoints.append((APname, apDownload, apUpload, parentSite, devicesForThisAP))
	
	# Sort devices into bins by AP, for scenario shapeBySite = False
	result = collections.defaultdict(list)
	for d in devices:
		result[d['AP']].append(d)
	devicesByAP = list(result.values())
	# If no AP is specified for a device in Shaper.csv, it is placed under this 'default' AP shaper, set to bandwidth max at edge
	accessPointDownloadMbps['none'] = upstreamBandwidthCapacityDownloadMbps
	accessPointUploadMbps['none'] = upstreamBandwidthCapacityUploadMbps
	
	# If an AP is specified for a device in Shaper.csv, but AP is not listed in AccessPoints.csv, raise exception
	for device in devices:
		if (device['AP'] not in accessPointNamesOnly):
			print(device['AP'])
			raise ValueError('AP for device ' + device['hostname'] + ' not listed in AccessPoints.csv')	
	
	# Load Sites
	sites = []
	with open('Sites.csv') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		next(csv_reader)
		for row in csv_reader:
			siteName, download, upload = row
			siteDownloadMbps = int(download)
			siteUploadMbps = int(upload)
			apsForThisSite = []
			for AP in accessPoints:
				APname, apDownload, apUpload, parentSite, devicesForThisAP = AP
				if parentSite == siteName:
					apsForThisSite.append((APname, apDownload, apUpload, parentSite, devicesForThisAP))
			sites.append((siteName, siteDownloadMbps, siteUploadMbps, apsForThisSite))
			
	#Clear Prior Settings
	clearPriorSettings(interfaceA, interfaceB)
	
	# XDP-CPUMAP-TC
	shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceA + ' --default --disable')
	shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceB + ' --default --disable')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceA + ' --lan')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceB + ' --wan')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --clear')
	shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceA)
	shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceB)
	
	# Find queues available
	queuesAvailable = 0
	path = '/sys/class/net/' + interfaceA + '/queues/'
	directory_contents = os.listdir(path)
	print(directory_contents)
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
			
	# Create MQ
	thisInterface = interfaceA
	shell('tc qdisc replace dev ' + thisInterface + ' root handle 7FFF: mq')
	for queue in range(queuesAvailable):
		shell('tc qdisc add dev ' + thisInterface + ' parent 7FFF:' + str(queue+1) + ' handle ' + str(queue+1) + ': htb default 2')
		shell('tc class add dev ' + thisInterface + ' parent ' + str(queue+1) + ': classid ' + str(queue+1) + ':1 htb rate '+ str(upstreamBandwidthCapacityDownloadMbps) + 'mbit ceil ' + str(upstreamBandwidthCapacityDownloadMbps) + 'mbit')
		shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue+1) + ':1 ' + fqOrCAKE)
		# Default class - traffic gets passed through this limiter with lower priority if not otherwise classified by the Shaper.csv
		# Only 1/4 of defaultClassCapacity is guarenteed (to prevent hitting ceiling of upstream), for the most part it serves as an "up to" ceiling.
		# Default class can use up to defaultClassCapacityDownloadMbps when that bandwidth isn't used by known hosts.
		shell('tc class add dev ' + thisInterface + ' parent ' + str(queue+1) + ':1 classid ' + str(queue+1) + ':2 htb rate ' + str(defaultClassCapacityDownloadMbps/4) + 'mbit ceil ' + str(defaultClassCapacityDownloadMbps) + 'mbit prio 5')
		shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue+1) + ':2 ' + fqOrCAKE)
	
	thisInterface = interfaceB
	shell('tc qdisc replace dev ' + thisInterface + ' root handle 7FFF: mq')
	for queue in range(queuesAvailable):
		shell('tc qdisc add dev ' + thisInterface + ' parent 7FFF:' + str(queue+1) + ' handle ' + str(queue+1) + ': htb default 2')
		shell('tc class add dev ' + thisInterface + ' parent ' + str(queue+1) + ': classid ' + str(queue+1) + ':1 htb rate '+ str(upstreamBandwidthCapacityUploadMbps) + 'mbit ceil ' + str(upstreamBandwidthCapacityUploadMbps) + 'mbit')
		shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue+1) + ':1 ' + fqOrCAKE)
		# Default class - traffic gets passed through this limiter with lower priority if not otherwise classified by the Shaper.csv.
		# Only 1/4 of defaultClassCapacity is guarenteed (to prevent hitting ceiling of upstream), for the most part it serves as an "up to" ceiling.
		# Default class can use up to defaultClassCapacityUploadMbps when that bandwidth isn't used by known hosts.
		shell('tc class add dev ' + thisInterface + ' parent ' + str(queue+1) + ':1 classid ' + str(queue+1) + ':2 htb rate ' + str(defaultClassCapacityUploadMbps/4) + 'mbit ceil ' + str(defaultClassCapacityUploadMbps) + 'mbit prio 5')
		shell('tc qdisc add dev ' + thisInterface + ' parent ' + str(queue+1) + ':2 ' + fqOrCAKE)
	print()

	#If shapeBySite == True, Shape by Site, AP and Client
	if shapeBySite:
		currentQueueCounter = 1
		queueMinorCounterDict = {}
		
		# :1 and :2 are used for root and default classes, so start each counter at :3
		for queueNum in range(queuesAvailable):
			queueMinorCounterDict[queueNum+1] = 3
		for site in sites:
			siteName, siteDownloadMbps, siteUploadMbps, apsForThisSite = site
			print("Adding site " + siteName)
			major = currentQueueCounter
			minor = queueMinorCounterDict[currentQueueCounter]
			thisSiteclassID = str(currentQueueCounter) + ':' + str(minor)
			# HTB + qdisc for each Site
			# Guarentee Site gets at least 1/4 of its capacity, allow up to its max capacity when network not at peak load
			shell('tc class add dev ' + interfaceA + ' parent ' + str(major) + ':1 classid ' + str(minor) + ' htb rate '+ str(round(siteDownloadMbps/4)) + 'mbit ceil '+ str(round(siteDownloadMbps)) + 'mbit prio 3') 
			shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
			shell('tc class add dev ' + interfaceB + ' parent ' + str(major) + ':1 classid ' + str(minor) + ' htb rate '+ str(round(siteUploadMbps/4)) + 'mbit ceil '+ str(round(siteUploadMbps)) + 'mbit prio 3') 
			shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
			minor += 1
			print()
			for AP in apsForThisSite:
				APname, apDownload, apUpload, parentSite, devicesForThisAP = AP
				print("Adding AP " + APname)
				# HTB + qdisc for each AP
				# Guarentee AP gets at least 1/4 of its capacity, allow up to its max capacity when network not at peak load
				shell('tc class add dev ' + interfaceA + ' parent ' + thisSiteclassID + ' classid ' + str(minor) + ' htb rate '+ str(round(apDownload/4)) + 'mbit ceil '+ str(round(apDownload)) + 'mbit prio 3') 
				shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
				shell('tc class add dev ' + interfaceB + ' parent ' + thisSiteclassID + ' classid ' + str(minor) + ' htb rate '+ str(round(apUpload/4)) + 'mbit ceil '+ str(round(apUpload)) + 'mbit prio 3') 
				shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
				thisAPclassID = str(currentQueueCounter) + ':' + str(minor)
				minor += 1
				print()
				for device in devicesForThisAP:
					print("Adding device " + device['hostname'])
					#HTB + qdisc for each device
					shell('tc class add dev ' + interfaceA + ' parent ' + thisAPclassID + ' classid ' + str(minor) + ' htb rate '+ str(device['downloadMin']) + 'mbit ceil '+ str(device['downloadMax']) + 'mbit prio 3') 
					shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
					shell('tc class add dev ' + interfaceB + ' parent ' + thisAPclassID + ' classid ' + str(minor) + ' htb rate '+ str(device['uploadMin']) + 'mbit ceil '+ str(device['uploadMax']) + 'mbit prio 3') 
					shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
					if device['ipv4']:
						parentString = str(major) + ':'
						flowIDstring = str(major) + ':' + str(minor)
						shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv4'] + ' --cpu ' + str(currentQueueCounter-1) + ' --classid ' + flowIDstring)
					#Once XDP-CPUMAP-TC handles IPv6, this can be added
					#if device['ipv6']:
					#	parentString = str(major) + ':'
					#	flowIDstring = str(major) + ':' + str(minor)
					#	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv6'] + ' --cpu ' + str(currentQueueCounter-1) + ' --classid ' + flowIDstring)
					device['qdisc'] = str(major) + ':' + str(minor)
					minor += 1
			queueMinorCounterDict[currentQueueCounter] = minor
			
			currentQueueCounter += 1
			if currentQueueCounter > queuesAvailable:
				currentQueueCounter = 1
	
	#If shapeBySite == False, shape by AP and Client only, not by Site
	else:
		currentQueueCounter = 1
		queueMinorCounterDict = {}
		# :1 and :2 are used for root and default classes, so start each counter at :3
		for queueNum in range(queuesAvailable):
			queueMinorCounterDict[queueNum+1] = 3
			
		for AP in devicesByAP:
			currentAPname = AP[0]['AP']
			thisAPdownload = accessPointDownloadMbps[currentAPname]
			thisAPupload = accessPointUploadMbps[currentAPname]
			major = currentQueueCounter
			minor = queueMinorCounterDict[currentQueueCounter]
			thisAPclassID = str(currentQueueCounter) + ':' + str(minor)
			# HTB + qdisc for each AP
			# Guarentee AP gets at least 1/4 of its radio capacity, allow up to its max radio capacity when network not at peak load
			shell('tc class add dev ' + interfaceA + ' parent ' + str(major) + ':1 classid ' + str(minor) + ' htb rate '+ str(round(thisAPdownload/4)) + 'mbit ceil '+ str(round(thisAPdownload)) + 'mbit prio 3') 
			shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
			shell('tc class add dev ' + interfaceB + ' parent ' + str(major) + ':1 classid ' + str(minor) + ' htb rate '+ str(round(thisAPupload/4)) + 'mbit ceil '+ str(round(thisAPupload)) + 'mbit prio 3') 
			shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
			minor += 1
			for device in AP:
				#HTB + qdisc for each device
				shell('tc class add dev ' + interfaceA + ' parent ' + thisAPclassID + ' classid ' + str(minor) + ' htb rate '+ str(device['downloadMin']) + 'mbit ceil '+ str(device['downloadMax']) + 'mbit prio 3') 
				shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
				shell('tc class add dev ' + interfaceB + ' parent ' + thisAPclassID + ' classid ' + str(minor) + ' htb rate '+ str(device['uploadMin']) + 'mbit ceil '+ str(device['uploadMax']) + 'mbit prio 3') 
				shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
				if device['ipv4']:
					parentString = str(major) + ':'
					flowIDstring = str(major) + ':' + str(minor)
					shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv4'] + ' --cpu ' + str(currentQueueCounter-1) + ' --classid ' + flowIDstring)
				#Once XDP-CPUMAP-TC handles IPv6, this can be added
				#if device['ipv6']:
				#	parentString = str(major) + ':'
				#	flowIDstring = str(major) + ':' + str(minor)
				#	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv6'] + ' --cpu ' + str(currentQueueCounter-1) + ' --classid ' + flowIDstring)
				device['qdisc'] = str(major) + ':' + str(minor)
				minor += 1
			queueMinorCounterDict[currentQueueCounter] = minor
			
			currentQueueCounter += 1
			if currentQueueCounter > queuesAvailable:
				currentQueueCounter = 1
	
	# Save devices to file to allow for statistics runs
	with open('devices.json', 'w') as outfile:
		json.dump(devices, outfile)
	
	# Done
	currentTimeString = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
	print("Successful run completed on " + currentTimeString)

if __name__ == '__main__':
	refreshShapers()
	print("Program complete")
