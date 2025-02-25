#!/usr/bin/python
from argparse import ArgumentParser
from pathlib import Path
from apachelogs import COMBINED, parse, LogEntry
import geoip2.database, geoip2.errors, geoip2.models
from multiprocessing import Pool, cpu_count, freeze_support, set_start_method

def parseLine(args: tuple[str, str]) -> LogEntry | str:
	line, logFormat = args
	try:
		return parse(logFormat, line)
	except:
		return line

if __name__ == '__main__':
	freeze_support()
	set_start_method('spawn')
	# Read arguments
	parser: ArgumentParser = ArgumentParser('Log Converter', description='Convert easily apache logs into databases to better analyze them')
	parser.add_argument('logfile', help='Log file to convert', type=Path)
	parser.add_argument('-o', '--output', help='Output file (default: name_of_log.sqlite3)', type=Path, default=None)
	parser.add_argument('-g', '--geolocate', help='Path to a MaxMind GeoIP City database to geolocate ip addresses found', type=Path, default=Path('GeoLite2-City.mmdb'))
	parser.add_argument('-a', '--asn', help='Path to a MaxMind GeoIP ASN database to geolocate ip addresses found', type=Path, default=Path('GeoLite2-ASN.mmdb'))
	parser.add_argument('-f', '--format', help='Custom log format (default COMBINED: %(default)s)', type=str, default=COMBINED)
	arguments = parser.parse_args()

	# More arguments checks
	print('Controllo parametri...')
	if not arguments.logfile.is_file():
		parser.error('Parameter logfile is not a valid file')

	if arguments.output is None:
		# TODO il file di destinazione deve andare nella stessa cartella del file di origine
		arguments.output = Path(arguments.logfile.name + '.sqlite3').resolve()

	ipLocator = None
	if arguments.geolocate is not None and arguments.geolocate.exists():
		if not arguments.geolocate.is_file():
			parser.error('Parameter geolocate is not a valid file')
		try:
			ipLocator: geoip2.database.Reader = geoip2.database.Reader(arguments.geolocate, locales=['en'])
		except:
			parser.error('Parameter geolocate is not a valid City database')

	asnLocator = None
	if arguments.asn is not None and arguments.asn.exists():
		if not arguments.asn.is_file():
			parser.error('Parameter asn is not a valid file')
		try:
			asnLocator: geoip2.database.Reader = geoip2.database.Reader(arguments.asn, locales=['en'])
		except:
			parser.error('Parameter asn is not a valid ASN database')
	
	# Database creation
	print('Parametri corretti, creo il database...')
	import sqlite3
	if arguments.output.exists():
		arguments.output.unlink(True)
	try:
		database: sqlite3.Connection = sqlite3.connect(arguments.output)
		querys: str = Path(__file__).resolve().with_name('create_database.sql').read_text()
		database.executescript(querys)
		database.commit()
	except Exception as e:
		parser.error(f'Could not create database: {e}')
	print('Database creato, inizio elaborazione...')
	
	# Start parsing
	import datetime
	from itertools import batched
	from time import time
	from contextlib import suppress
	from psutil import virtual_memory
	from sys import getsizeof

	sqlite3.register_adapter(datetime.datetime, lambda val: val.isoformat())

	def stimaMemoriaPerLinea(filePath: any, campione: int = 1000) -> int:
		memoria: int = 0
		with open(filePath, 'rb') as file:
			for _ in range(campione):
				linea = file.readline()
				if not linea:
					break
				memoria += getsizeof(linea)
		return memoria / campione if campione else 1
	
	def contaLinee(filePath: any) -> int:
		linee = 0
		with open(filePath, 'rb', buffering=0) as file:
			blocco = file.read(1024**2)
			while blocco:
				linee += blocco.count(b'\n')
				blocco = file.read(1024**2)
		return linee
	
	memoriaDisponibile: int = virtual_memory().available * 0.7
	memoriaPerLinea: int = stimaMemoriaPerLinea(arguments.logfile)
	massimoLineeInMemoria: int = int(memoriaDisponibile // memoriaPerLinea)

	totaleLinee: int = contaLinee(arguments.logfile)
	batchSize: int = max(1, massimoLineeInMemoria // cpu_count())
	chunkSize: int = max(1, batchSize // cpu_count())

	print(f'Elaborazione di {totaleLinee} linee con {cpu_count()} core, {batchSize} linee per batch e {chunkSize} linee per core')
	print(f'Stima memoria per linea: {memoriaPerLinea} byte, memoria disponibile: {memoriaDisponibile} byte')

	with open(arguments.logfile, 'r') as file:
		with Pool() as p:
			contatore: int = 1
			startProcess: float = time()
			for batch in batched(file, batchSize):
				for parsed in p.imap_unordered(parseLine, ((line, arguments.format) for line in batch), chunksize=chunkSize):
					if isinstance(parsed, LogEntry):
						requestId = database.execute('INSERT INTO requests VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)', (parsed.request_time, parsed.remote_host, parsed.request_line, parsed.final_status, parsed.bytes_sent, parsed.remote_user, parsed.entry)).lastrowid
						database.executemany('INSERT INTO headers VALUES (?, ?, ?)', ((requestId, header, value) for header, value in parsed.headers_in.items()))
						data: dict = {
							'ip_address': parsed.remote_host,
							'city': None,
							'postal': None,
							'country': None,
							'continent': None,
							'latitude': None,
							'longitude': None,
							'radius': None,
							'asn': None,
							'asn_org': None
						}
						if ipLocator is not None:
							with suppress(geoip2.errors.AddressNotFoundError):
								ipLocation: geoip2.models.City = ipLocator.city(parsed.remote_host)
								data.update({
									'city': ipLocation.city.name,
									'postal': ipLocation.postal.code,
									'country': ipLocation.country.name,
									'continent': ipLocation.continent.name,
									'latitude': ipLocation.location.latitude,
									'longitude': ipLocation.location.longitude,
									'radius': ipLocation.location.accuracy_radius
								})
						if asnLocator is not None:
							with suppress(geoip2.errors.AddressNotFoundError):
								asnLocation: geoip2.models.ASN = asnLocator.asn(parsed.remote_host)
								data.update({
									'asn': asnLocation.autonomous_system_number,
									'asn_org': asnLocation.autonomous_system_organization
								})
						database.execute('INSERT OR REPLACE INTO ip_geolocation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (data['ip_address'], data['city'], data['postal'], data['country'], data['continent'], data['latitude'], data['longitude'], data['radius'], data['asn'], data['asn_org']))
					elif isinstance(parsed, str):
						database.execute('INSERT INTO requests (raw_line) VALUES (?)', (parsed,))
					contatore += 1
					elapsed: float = time() - startProcess
					print(f'{contatore}/{totaleLinee} {contatore//elapsed:.0f}r/s {elapsed:.0f}s', end='\r')
				database.commit()

	# Cleanup and close
	print(f'Processo completato in {time() - startProcess:.0f} secondi')
	database.close()
	if ipLocator is not None:
		ipLocator.close()
	if asnLocator is not None:
		asnLocator.close()