#Some references (architecture mainly) from https://github.com/learnpyqt/15-minute-apps/tree/master/browser
#udp scan logic from https://github.com/remzmike/python-kports-portscanner/blob/master/kports.py

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtPrintSupport import *
import socket
import threading
import sys
from datetime import datetime
import errno
import os
import sys
import time
from netaddr import IPNetwork

class MainWindow(QDialog):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.originalPalette = QApplication.palette()

        styleComboBox = QComboBox()
        styleComboBox.addItems(QStyleFactory.keys())

        self.createInputLayout()
        self.createProgressBar()

        mainLayout = QGridLayout()
        mainLayout.addWidget(self.inputLayout,0,0, 1, 0)
        mainLayout.addWidget(self.progressBar, 1, 0, 1, 2)
        mainLayout.setRowStretch(1, 1)
        mainLayout.setRowStretch(2, 1)
        mainLayout.setColumnStretch(0, 1)
        mainLayout.setColumnStretch(1, 1)
        self.setLayout(mainLayout)

        self.setWindowTitle("PortScanner")
        QApplication.setStyle(QStyleFactory.create("Fusion"))

    def enablePort(self):
        self.portInput.setDisabled(not self.PortcheckBox.isChecked())

    def TCP_connect(self,ip, port_number,output):
        #some references from https://stackoverflow.com/a/38210023 ; https://johanneskinzig.de/index.php/it-security/12-port-scanning-and-banner-grabbing-with-python

        if(self.TCPradioButton.isChecked()):
            socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            packet_type = 'tcp'

            socket.setdefaulttimeout(4)
            result = socket_obj.connect_ex((ip,int(port_number)))
            socket_obj.close()

            if result == 0:
                try:
                    machine_hostname = socket.gethostbyaddr(ip)[0]
                except:
                    machine_hostname = 'Not found'
                try:
                    service = socket.getservbyport(port_number)
                except :
                    service = "Not found"
                output_str = "open port detected: " + str(ip) + " \t-- Port: " + str(port_number)+'\\'+packet_type + " \t-- Service: " + str(service) + " \t-- Hostname: " + str(machine_hostname)
                output[port_number] = (True,output_str)

            else:
                output[port_number] = (False,'')


        else:
            packet_type = 'udp'

            initial_sends=8
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            status = None
            sock.setblocking(0)
            try:
                sock.connect((ip, int(port_number)))
            except:
                output[port_number] = (False,'')
                return
            for i in range(initial_sends):
                try:
                    sock.send(b'\x00')
                except socket.error as ex:
                    if ex.errno == errno.ECONNREFUSED:
                        status = False
                        sock.close()
                        break
                    else:
                        raise
            
            if status == None:
                try:
                    machine_hostname = socket.gethostbyaddr(ip)[0]
                except:
                    machine_hostname = 'Not found'
                try:
                    service = socket.getservbyport(port_number)
                except :
                    service = "Not found"
                sock.close()
                output_str = "open port detected: " + str(ip) + " \t-- Port: " + str(port_number)+'\\'+packet_type + " \t-- Service: " + str(service) + " \t-- Hostname: " + str(machine_hostname)
                output[port_number] = (True,output_str)
            else:
                output[port_number] = (False,'')


    def scan_ports(self,host_ip,net):
        #from https://stackoverflow.com/a/38210023
        threads = []    
        output = {}

        if(not net):
            for i in self.for_range:
                t = threading.Thread(target=self.TCP_connect, args=(host_ip, i,output))
                threads.append(t)

            for thread in threads:
                thread.start()
            
            for thread in threads:
                thread.join()
                self.advanceProgressBar()

        else:
            for i in self.for_range:
                self.TCP_connect(host_ip,i,output)
                self.advanceProgressBar()

        for i in self.for_range:
            if output[i][0]:
                
                self.output += output[i][1] + '\n\n\n'
                



    def doScan(self):
        self.scanPushButton.setDisabled(True)
        remoteServerIP = self.ipInput.text()
        portInput = self.portInput.text()

        total_range = []

        if(self.PortcheckBox.isChecked()):
            if ',' in portInput:
                for rang in portInput.split(','):
                    total_range += range(int(rang.split('-')[0]),int(rang.split('-')[1]))
            else:
                if'-' in portInput:
                    total_range += range(int(portInput.split('-')[0]),int(portInput.split('-')[1]))
                else:
                    total_range = [portInput]
        else:
            total_range = range(6000)
        self.for_range = total_range
        self.updateProgressBar(len(self.for_range))
        self.output = ""
        if('/' in remoteServerIP):
            self.updateProgressBar(len(self.for_range) * len(IPNetwork(remoteServerIP)))
            
            threads = []    
            output = {}

            for ip in IPNetwork(remoteServerIP):
                net_ip = str(ip)
                t = threading.Thread(target=self.scan_ports, args=(net_ip,True))
                threads.append(t)

            for thread in threads:
                thread.start()
            
            for thread in threads:
                thread.join()

        else:
            self.scan_ports(remoteServerIP,False)

        self.scanPushButton.setDisabled(False)

        self.outputTextEdit.setPlainText(self.output)


    def createInputLayout(self):
        self.inputLayout = QGroupBox()
        self.TCPradioButton = QRadioButton("TCP")
        self.UDPradioButton= QRadioButton("UDP")
        self.TCPradioButton.setChecked(True)

        ipLabel = QLabel("IP:")

        self.ipInput = QLineEdit()
        ipLabel.setBuddy(self.ipInput)
        self.ipInput.setText("127.0.0.1")

        self.portInput = QLineEdit()
        # self.portInput.setPlaceholderText("21-23,443-1000")
        self.portInput.setText("21-23,443-1000")
        self.portInput.setDisabled(True)

        self.PortcheckBox = QCheckBox("Specify Port:")
        self.PortcheckBox.setCheckState(False)
        self.PortcheckBox.stateChanged.connect(self.enablePort)

        allmainLayout = QHBoxLayout()

        self.outputTextEdit = QTextEdit()
        self.outputTextEdit.setPlainText("")

        layout = QGridLayout()
        firstrowLayout = QHBoxLayout()
        firstrowLayout.addWidget(ipLabel)
        firstrowLayout.addWidget(self.ipInput)
        firstrowLayout.addWidget(self.TCPradioButton)
        firstrowLayout.addWidget(self.UDPradioButton)
        firstrowLayout.addStretch(1)

        secondrowLayout = QHBoxLayout()
        secondrowLayout.addWidget(self.PortcheckBox)
        secondrowLayout.addWidget(self.portInput)

        self.scanPushButton = QPushButton("Scan")
        self.scanPushButton.setDefault(True)
        self.scanPushButton.clicked.connect(self.doScan)

        layout.addLayout(firstrowLayout,0,0)
        layout.addLayout(secondrowLayout,1,0)
        layout.addWidget(self.scanPushButton,2,0,alignment=Qt.AlignRight)


        allmainLayout.addLayout(layout)
        allmainLayout.addWidget(self.outputTextEdit)

        self.inputLayout.setLayout(allmainLayout)    

    def createProgressBar(self):
        self.progressBar = QProgressBar()
        self.progressBar.setRange(0, 1000)
        self.progressBar.setValue(0)
        self.progressJump = 1

    def updateProgressBar(self, maxVal):
        self.progressBar.setRange(0, maxVal)
        self.progressBar.setValue(0)

    def advanceProgressBar(self):
        curVal = self.progressBar.value()
        maxVal = self.progressBar.maximum()
        self.progressBar.setValue(curVal + self.progressJump)




app = QApplication(sys.argv)
app.setApplicationName("Portscanner")

gallery = MainWindow()
gallery.show()

app.exec_()