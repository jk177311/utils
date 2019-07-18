# This script generates server.pem with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# Run the script:
#    python https-server.py
# Then in your browser visit:
#    https://localhost:4443
# Example how to upload using curl:
#   curl -k -v -X POST https://localhost:4443/<filename> -T /path/to/file
#
# https://stackoverflow.com/questions/46210672/python-2-7-streaming-http-server-supporting-multiple-connections-on-one-port
# 

import argparse
import logging
import atexit
import BaseHTTPServer, SimpleHTTPServer
import ssl
import os
import posixpath
import mimetypes
import re
import tempfile
import threading
import time
import socket
import shutil
import cgi
from subprocess import call
from StringIO import StringIO
from io import BytesIO

# create logger with 'spam_application'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('server.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

temp_directory = tempfile.mkdtemp()
ssl_cert_path = "{}/server.pem".format(temp_directory)

class CustomHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

	def directory_items(self, path):
		try:
			directory_items = os.listdir(path)
		except os.error:
			self.send_error(404, "No permission to list directory.")
			return None
		return directory_items

	def do_GET(self):
		logger.debug('GET')
		self.send_response(200)
		
		relative_path = self.path
		logger.debug("Relative Path = {}".format(relative_path))
		if relative_path.startswith('/'):
			relative_path = relative_path[1:]
		server_root_path = os.getcwd()
		logger.debug("Server root path = {}".format(server_root_path))
		directory_path = os.path.join(server_root_path, relative_path)
		if directory_path.endswith('/'):
			directory_path = directory_path[:-1]
		logger.debug("Directory path = {}".format(directory_path))
		path = os.path.join(server_root_path, relative_path)
		logger.debug("Path = {}".format(path))
		if os.path.isdir(path):
			self.send_header("Content-type", "text/html")
			self.end_headers()
			directory_items = self.directory_items(directory_path)
			self.wfile.write("<html><head><tile>Directory listing for /{}.</title></head>".format(relative_path))
			logger.debug("Directory contents = {}".format(directory_items))
			head, tail = os.path.split(relative_path)
			logger.debug(head)
			logger.debug(tail)
			parent_directory = "/{}".format(head)
			logger.debug("Parent Directory = {}".format(parent_directory))
			self.wfile.write('<li><a href={}>..</li>'.format(parent_directory))
			for item in directory_items:
				logger.debug("Item = {}".format(item))
				path_to_item = "{0}/{1}".format(relative_path, item)
				logger.debug("Path to item = {}".format(path_to_item))
				self.wfile.write('<li><a href={0}>{1}</li>'.format(path_to_item, item))
			self.wfile.write("</body></html>")
		elif os.path.isfile(path):
			with open(path, 'rb') as f:
				self.send_header('Content-Type', 'application/octet-stream')
				self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(os.path.basename(path)))
				self.send_header('Content-Length', os.path.getsize(path)) 
				self.end_headers()
				shutil.copyfileobj(f, self.wfile)
		else:
			self.send_response(404)
			self.send_header('Content-Type', 'text/html')
			self.end_headers()
			self.wfile.write('404 not found')


	def do_HEAD(self):
		logger.info('HEAD')
		f = self.send_head()
		if f:
			f.close()

	def do_POST(self):
		logger.info('POST')
		relative_path = self.path
		if relative_path.startswith('/'):
			relative_path = relative_path[1:]
		logger.debug("Relative path = {}".format(relative_path))
		server_root_path = os.getcwd()
		path = os.path.join(server_root_path, relative_path)
		logger.debug("Path = {}".format(path))
		content_type = self.headers.get('Content-Type')
		logger.debug("Content-Type = {}".format(content_type))
		content_length = int(self.headers['Content-Length'])
		logger.debug("Content Length = {}".format(content_length))
		post_data = self.rfile.read(content_length)
		self.send_header('Expect', '100-continue')
		
		chunks_of_post_data = self.divide_chunks(post_data, 4096)
		
		number_of_uploaded_bytes = 0
		with open(path, 'wb+') as f:
			logger.debug('Opening {} for writing...'.format(path))
			for chunk in chunks_of_post_data:
				f.write(chunk)
		
		file_size = os.path.getsize(path)

		response = BytesIO()
		post_request_from = 'POST request from {} \n'.format(self.address_string())
		logger.debug(post_request_from)
		response.write(post_request_from)
		
		number_of_bytes_saved_to_file = '{0} bytes written to {1} \n'.format(file_size, relative_path)
		logger.debug(number_of_bytes_saved_to_file)
		response.write(number_of_bytes_saved_to_file)
		self.wfile.write(response.getvalue())
		self.send_response(201)
				
	def do_PUT(self):
		logger.info('PUT')
		relative_path = self.path
		if relative_path.startswith('/'):
			relative_path = relative_path[1:]
		logger.debug("Relative path = {}".format(relative_path))
		server_root_path = os.getcwd()
		path = os.path.join(server_root_path, relative_path)
		logger.debug("Path = {}".format(path))
		content_type = self.headers.get('Content-Type')
		logger.debug("Content-Type = {}".format(content_type))
		content_length = int(self.headers['Content-Length'])
		logger.debug("Content Length = {}".format(content_length))
		post_data = self.rfile.read(content_length)
		self.send_header('Expect', '100-continue')
		if os.path.exists(path):
			with open(path, 'wb') as f:
				f.write(post_data)
			self.send_header('Content-Location', relative_path)
			self.send_response(204)
		else:
			with open(path, 'wb+') as f:
				f.write(post_data)
			self.send_header('Content-Location', relative_path)
			self.send_response(201)

	def do_DELETE(self):
		logger.info('DELETE')
		relative_path = self.path
		if relative_path.startswith('/'):
			relative_path = relative_path[1:]
		logger.debug("Relative path = {}".format(relative_path))
		server_root_path = os.getcwd()
		path = os.path.join(server_root_path, relative_path)
		logger.debug("Path = {}".format(path))
		
		try:
			os.remove(path)
		except Exception as e:
			logger.error(e)
		if not os.path.exists(path):
			self.send_response(204)

	def divide_chunks(self, the_list, size_of_chunks):
		# loop until lengh of the list
		for i in range(0, len(the_list), size_of_chunks):
			yield the_list[i:i + size_of_chunks]

class Thread(threading.Thread):
	def __init__(self, ssl, port, socket, bind_to_address):
		threading.Thread.__init__(self)
		self.ssl = ssl
		self.socket = socket
		self.bind_to_address = bind_to_address
		self.port = port
		self.daemon = True
		self.start()
	
	def run(self):
		httpd = BaseHTTPServer.HTTPServer((self.bind_to_address, self.port), CustomHTTPRequestHandler, False)
					
		# Prevent the HTTP server from re-binding every handler.
		# https://stackoverflow.com/questions/46210672/
		if self.ssl:
			httpd.socket = ssl.wrap_socket(self.socket, certfile=ssl_cert_path, server_side=True)
		else:
			httpd.socket = self.socket
		httpd.server_bind = self.server_close = lambda self: None
		httpd.serve_forever()

def create_ssl_cert():
	logging.info('Creating SSL certificate at {}'.format(ssl_cert_path))
	devnull = open(os.devnull, 'wb')
	try:
		ssl_exec_list = ['openssl', 'req', '-new', '-x509', '-keyout', ssl_cert_path, 
		'-out', ssl_cert_path, '-days', '365', '-nodes',
		'-subj', '/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com']
		call(ssl_exec_list, stdout=devnull, stderr=devnull)
	except Exception as exception:
		logging.error(exception)
		exit(1)

		logging.info('Self signed ssl certificate created at {}'.format(ssl_cert_path))

def exit_handler(ssl):
	if ssl is True:
		# remove certificate file at exit
		shutil.rmtree(temp_directory)
		logging.info('Exiting https server...')

def threads_are_running(threads):
	for t in threads:
		if t.isAlive():
			return True
		else:
			return False

def launch_server(ssl, port, sock, bind_to_address):
	try:
		logger.info('Launching 100 listener threads.')
		threads = [Thread(ssl, port, sock, bind_to_address) for i in range(100)]
		while True:
			time.sleep(30)
			x = threads_are_running(threads)
			logger.debug(x)
			if x == False:
				launch_server(ssl, port, sock, bind_to_address)
	except Exception as e:
		logger.error(e)

def server(ssl, port):

	logger.debug("ssl : {}".format(ssl))
	logger.debug("port : {}".format(port))

	atexit.register(exit_handler, ssl)
	if ssl is True:
		create_ssl_cert()

	# Create ONE socket.
	# bind_to_address
	# This in with the text localhost if you want it to only listen to 127.0.0.1. 
	# Leave it blank to have it listen to all IPv4 interfaces (0.0.0.0).
	# bind_to_address = '0.0.0.0'
	bind_to_address = ''
	addr = (bind_to_address, int(port))
	sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(addr)
	sock.listen(5)
	
	logger.debug("address : {}".format(addr))

	try:
		launch_server(ssl, port, sock, bind_to_address)
	except Exception as e:
		logger.error(e)

def main(args):
	
	server(args.ssl, args.port)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('--ssl', help='Use HTTPS', action='store_true', default=False)
	parser.add_argument('--port', help='Specify port other than 8000.', default=8000)
	args = parser.parse_args()
	main(args)
