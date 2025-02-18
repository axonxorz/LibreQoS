# v1.1 alpha

import random
import logging
import os
import io
import json
import csv
import subprocess
from subprocess import PIPE
import ipaddress
from ipaddress import IPv4Address, IPv6Address
import time
from datetime import date, datetime
from ispConfig import fqOrCAKE, upstreamBandwidthCapacityDownloadMbps, upstreamBandwidthCapacityUploadMbps, defaultClassCapacityDownloadMbps, defaultClassCapacityUploadMbps, interfaceA, interfaceB, shapeBySite, enableActualShellCommands, runShellCommandsAsSudo
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
	if enableActualShellCommands:
		shell('tc filter delete dev ' + interfaceA)
		shell('tc filter delete dev ' + interfaceA + ' root')
		shell('tc qdisc delete dev ' + interfaceA + ' root')
		shell('tc qdisc delete dev ' + interfaceA)
		shell('tc filter delete dev ' + interfaceB)
		shell('tc filter delete dev ' + interfaceB + ' root')
		shell('tc qdisc delete dev ' + interfaceB + ' root')
		shell('tc qdisc delete dev ' + interfaceB)

def refreshShapers():
	tcpOverheadFactor = 1.09

	# Load Devices
	devices = []
	with open('Shaper.csv') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		next(csv_reader)
		for row in csv_reader:
			deviceID, ParentNode, mac, hostname,ipv4, ipv6, downloadMin, uploadMin, downloadMax, uploadMax = row
			ipv4 = ipv4.strip()
			ipv6 = ipv6.strip()
			if ParentNode == "":
				ParentNode = "none"
			ParentNode = ParentNode.strip()
			thisDevice = {
			  "id": deviceID,
			  "mac": mac,
			  "ParentNode": ParentNode,
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
	
	#Load network heirarchy
	with open('network.json', 'r') as j:
		network = json.loads(j.read())
	
	#Find the bandwidth minimums for each node by combining mimimums of devices lower in that node's heirarchy
	def findBandwidthMins(data, depth):
		tabs = '   ' * depth
		minDownload = 0
		minUpload = 0
		for elem in data:
			
			for device in devices:
				if elem == device['ParentNode']:
					minDownload += device['downloadMin']
					minUpload += device['uploadMin']
			if 'children' in data[elem]:
				minDL, minUL = findBandwidthMins(data[elem]['children'], depth+1)
				minDownload += minDL
				minUpload += minUL
			data[elem]['downloadBandwidthMbpsMin'] = minDownload
			data[elem]['uploadBandwidthMbpsMin'] = minUpload
		return minDownload, minUpload
	
	minDownload, minUpload = findBandwidthMins(network, 0)

	#Clear Prior Settings
	clearPriorSettings(interfaceA, interfaceB)

	# Find queues available
	queuesAvailable = 0
	path = '/sys/class/net/' + interfaceA + '/queues/'
	directory_contents = os.listdir(path)
	#print(directory_contents)
	for item in directory_contents:
		if "tx-" in str(item):
			queuesAvailable += 1
	print("This Network Interface Card has " + str(queuesAvailable) + " queues avaialble.")
	
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

	# XDP-CPUMAP-TC
	shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceA + ' --default --disable')
	shell('./xdp-cpumap-tc/bin/xps_setup.sh -d ' + interfaceB + ' --default --disable')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceA + ' --lan')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu --dev ' + interfaceB + ' --wan')
	shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --clear')
	shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceA)
	shell('./xdp-cpumap-tc/src/tc_classify --dev-egress ' + interfaceB)

	# Create MQ qdisc for each interface
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

	#Parse network.json. For each tier, create corresponding HTB and leaf classes
	devicesShaped = []
	parentNodes = []
	def traverseNetwork(data, depth, major, minor, queue, parentClassID, parentMaxDL, parentMaxUL):
		tabs = '   ' * depth
		for elem in data:
			print(tabs + elem)
			elemClassID = str(major) + ':' + str(minor)
			#Cap based on this node's max bandwidth, or parent node's max bandwidth, whichever is lower
			elemDownloadMax = min(data[elem]['downloadBandwidthMbps'],parentMaxDL)
			elemUploadMax = min(data[elem]['uploadBandwidthMbps'],parentMaxUL)
			#Based on calculations done in findBandwidthMins(), determine optimal HTB rates (mins) and ceils (maxs)
			#The max calculation is to avoid 0 values, and the min calculation is to ensure rate is not higher than ceil
			elemDownloadMin = round(elemDownloadMax*.95)
			elemUploadMin = round(elemUploadMax*.95)
			print(tabs + "Download:  " + str(elemDownloadMin) + " to " + str(elemDownloadMax) + " Mbps")
			print(tabs + "Upload:    " + str(elemUploadMin) + " to " + str(elemUploadMax) + " Mbps")
			print(tabs, end='')
			shell('tc class add dev ' + interfaceA + ' parent ' + parentClassID + ' classid ' + str(minor) + ' htb rate '+ str(round(elemDownloadMin)) + 'mbit ceil '+ str(round(elemDownloadMax)) + 'mbit prio 3') 
			print(tabs, end='')
			shell('tc class add dev ' + interfaceB + ' parent ' + parentClassID + ' classid ' + str(minor) + ' htb rate '+ str(round(elemUploadMin)) + 'mbit ceil '+ str(round(elemUploadMax)) + 'mbit prio 3') 
			print()
			thisParentNode =	{
								"parentNodeName": elem,
								"classID": elemClassID,
								"downloadMax": elemDownloadMax,
								"uploadMax": elemUploadMax,
								}
			parentNodes.append(thisParentNode)
			minor += 1
			for device in devices:
				#If a device from Shaper.csv lists this elem as its Parent Node, attach it as a leaf to this elem HTB
				if elem == device['ParentNode']:
					maxDownload = min(device['downloadMax'],elemDownloadMax)
					maxUpload = min(device['uploadMax'],elemUploadMax)
					minDownload = min(device['downloadMin'],maxDownload)
					minUpload = min(device['uploadMin'],maxUpload)
					print(tabs + '   ' + device['hostname'])
					print(tabs + '   ' + "Download:  " + str(minDownload) + " to " + str(maxDownload) + " Mbps")
					print(tabs + '   ' + "Upload:    " + str(minUpload) + " to " + str(maxUpload) + " Mbps")
					print(tabs + '   ', end='')
					shell('tc class add dev ' + interfaceA + ' parent ' + elemClassID + ' classid ' + str(minor) + ' htb rate '+ str(minDownload) + 'mbit ceil '+ str(maxDownload) + 'mbit prio 3')
					print(tabs + '   ', end='')
					shell('tc qdisc add dev ' + interfaceA + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
					print(tabs + '   ', end='')
					shell('tc class add dev ' + interfaceB + ' parent ' + elemClassID + ' classid ' + str(minor) + ' htb rate '+ str(minUpload) + 'mbit ceil '+ str(maxUpload) + 'mbit prio 3') 
					print(tabs + '   ', end='')
					shell('tc qdisc add dev ' + interfaceB + ' parent ' + str(major) + ':' + str(minor) + ' ' + fqOrCAKE)
					if device['ipv4']:
						parentString = str(major) + ':'
						flowIDstring = str(major) + ':' + str(minor)
						print(tabs + '   ', end='')
						shell('./xdp-cpumap-tc/src/xdp_iphash_to_cpu_cmdline --add --ip ' + device['ipv4'] + ' --cpu ' + str(queue-1) + ' --classid ' + flowIDstring)
						device['qdisc'] = flowIDstring
						if device['hostname'] not in devicesShaped:
							devicesShaped.append(device['hostname'])
					print()
					minor += 1
			#Recursive call this function for children nodes attached to this node
			if 'children' in data[elem]:
				#We need to keep tabs on the minor counter, because we can't have repeating class IDs. Here, we bring back the minor counter from the recursive function
				minor = traverseNetwork(data[elem]['children'], depth+1, major, minor+1, queue, elemClassID, elemDownloadMax, elemUploadMax)
			#If top level node, increment to next queue / cpu core
			if depth == 0:
				if queue >= queuesAvailable:
					queue = 1
					major = queue
				else:
					queue += 1
					major += 1
		return minor
	
	#Here is the actual call to the recursive traverseNetwork() function. finalMinor is not used.
	finalMinor = traverseNetwork(network, 0, major=1, minor=3, queue=1, parentClassID="1:1", parentMaxDL=upstreamBandwidthCapacityDownloadMbps, parentMaxUL=upstreamBandwidthCapacityUploadMbps)
	
	#Recap
	for device in devices:
		if device['hostname'] not in devicesShaped:
			print('Device ' + device['hostname'] + ' was not shaped. Please check to ensure its parent Node is listed in network.json.')
	
	#Save for stats
	with open('statsByDevice.json', 'w') as infile:
		json.dump(devices, infile)
	with open('statsByParentNode.json', 'w') as infile:
		json.dump(parentNodes, infile)

	# Done
	currentTimeString = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
	print("Successful run completed on " + currentTimeString)

if __name__ == '__main__':
	refreshShapers()
	print("Program complete")
