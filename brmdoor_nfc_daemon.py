#!/usr/bin/env python

import threading
import Queue
import logging

from binascii import hexlify

from ConfigParser import SafeConfigParser

from brmdoor_nfc import NFCDevice, NFCError
from brmdoor_authenticator import UidAuthenticator

class NfcThread(threading.Thread):
	"""Thread reading data from NFC reader"""
	        
	def __init__(self, uidQueue):
		"""Create thread reading UIDs from PN53x reader.
		"""
		self.nfc = NFCDevice()
		self.uidQueue = uidQueue
		threading.Thread.__init__(self)

	def run(self):
		"""
		Waits for a card to get into reader field. Reads its UID and
		stores it into uidQueue for later authentication check.
		"""
		try:
			uid_hex = hexlify(self.nfc.scanUID())
			logging.info("Got UID %s" % uid_hex)
			self.uidQueue.put(uid_hex)
		except NFCError, e:
			logging.warn("Failed to wait for RFID card", e)
			

class UnlockThread(threading.Thread):
	"""Thread checking UIDs whether they are authorized"""
	        
	def __init__(self, uidQueue, authenticatorDBFname):
		"""Create thread reading UIDs from PN53x reader.
		"""
		self.uidQueue = uidQueue
		self.authenticatorDBFname = authenticatorDBFname
		threading.Thread.__init__(self)

	def run(self):
		"""
		Reads hex UIDs from queue, tries to find them in sqlite database.
		
		If match in database is found, then unlock the lock (for now
		only logs).
		"""
		self.authenticator = UidAuthenticator(self.authenticatorDBFname)
		while True:
			uid_hex = self.uidQueue.get()
			
			record = self.authenticator.fetchUidRecord(uid_hex)
			
			if record is None:
				logging.info("Unknown UID %s", uid_hex)
			else:
				logging.info("Unlocking for %s", record)

if __name__  == "__main__":
	uidQueue = Queue.Queue(512)
	#TODO use SafeConfigParser to get actual config data
	
	nfcThread = NfcThread(uidQueue)
	nfcThread.setDaemon(True)
	nfcThread.start()
	
	unlockThread = UnlockThread(uidQueue, "test_uids_db.sqlite")
	unlockThread.setDaemon(True)
	unlockThread.start()
	
	uidQueue.join()
	