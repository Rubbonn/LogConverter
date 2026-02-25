#!/usr/bin/python
from argparse import ArgumentParser
from pathlib import Path
from apachelogs import COMBINED, parse, LogEntry
import geoip2.database, geoip2.errors, geoip2.models
from multiprocessing import Pool, cpu_count, freeze_support, set_start_method
from typing import Optional

# Global log format used by worker processes (set via Pool initializer)
_LOG_FORMAT: str | None = None

def _init_worker(fmt: str):
	global _LOG_FORMAT
	_LOG_FORMAT = fmt

def parseLine(line: str) -> LogEntry | str:
	try:
		return parse(_LOG_FORMAT, line)  # type: ignore[arg-type]
	except Exception:
		return line

if __name__ == '__main__':
	freeze_support()
	set_start_method('spawn', force=True)
	# Read arguments
	parser: ArgumentParser = ArgumentParser('Log Converter', description='Convert easily apache logs into databases to better analyze them')
	parser.add_argument('logfile', help='Log file to convert', type=Path, nargs='+')
	parser.add_argument('-o', '--output', help='Output file (default: name_of_log.sqlite3)', type=Path, default=None)
	parser.add_argument('-g', '--geolocate', help='Path to a MaxMind GeoIP City database to geolocate ip addresses found', type=Path, default=Path('GeoLite2-City.mmdb'))
	parser.add_argument('-a', '--asn', help='Path to a MaxMind GeoIP ASN database to geolocate ip addresses found', type=Path, default=Path('GeoLite2-ASN.mmdb'))
	parser.add_argument('-f', '--format', help='Custom log format (default COMBINED: %(default)s)', type=str, default=COMBINED)
	arguments = parser.parse_args()

	# More arguments checks
	print('Controllo parametri...')
	if not all(file.is_file() for file in arguments.logfile):
		parser.error('Parameter logfile is not a valid file')
	if arguments.output is None:
		arguments.output = Path(arguments.logfile[0].with_suffix(''.join(arguments.logfile[0].suffixes) + '.sqlite3')).resolve()
	ipLocator: Optional[geoip2.database.Reader] = None
	if arguments.geolocate is not None and arguments.geolocate.exists():
		if not arguments.geolocate.is_file():
			parser.error('Parameter geolocate is not a valid file')
		try:
			ipLocator = geoip2.database.Reader(arguments.geolocate, locales=['en'])
		except:
			parser.error('Parameter geolocate is not a valid City database')

	asnLocator: Optional[geoip2.database.Reader] = None
	if arguments.asn is not None and arguments.asn.exists():
		if not arguments.asn.is_file():
			parser.error('Parameter asn is not a valid file')
		try:
			asnLocator = geoip2.database.Reader(arguments.asn, locales=['en'])
		except:
			parser.error('Parameter asn is not a valid ASN database')
	
	# Database creation
	print('Parametri corretti, creo il database...')
	import sqlite3
	if arguments.output.exists():
		arguments.output.unlink(True)
	try:
		database: sqlite3.Connection = sqlite3.connect(arguments.output)
		# SQLite performance pragmas to speed up bulk inserts without changing functionality
		database.execute('PRAGMA journal_mode=WAL')
		database.execute('PRAGMA synchronous=NORMAL')
		database.execute('PRAGMA temp_store=MEMORY')
		database.execute('PRAGMA cache_size=-200000')
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

	# Caches to avoid repeated GeoIP lookups and duplicate inserts
	seen_ips: set[str] = set()
	_city_cache: dict[str, dict] = {}
	_asn_cache: dict[str, dict] = {}

	for file in arguments.logfile:
		print(f'Elaborazione del file {file.name}...')
		memoriaDisponibile: int = virtual_memory().available * 0.7
		memoriaPerLinea: int = stimaMemoriaPerLinea(file)
		massimoLineeInMemoria: int = int(memoriaDisponibile // memoriaPerLinea)

		totaleLinee: int = contaLinee(file)
		batchSize: int = max(1, massimoLineeInMemoria // cpu_count())
		chunkSize: int = max(1, batchSize // cpu_count())

		print(f'Elaborazione di {totaleLinee} linee con {cpu_count()} core, {batchSize} linee per batch e {chunkSize} linee per core')
		print(f'Stima memoria per linea: {memoriaPerLinea} byte, memoria disponibile: {memoriaDisponibile} byte')

		with open(file, 'r', buffering=1024*1024) as file_reader:
			with Pool(initializer=_init_worker, initargs=(arguments.format,)) as p:
				contatore: int = 0
				startProcess: float = time()
				lastPrint: float = startProcess
				for batch in batched(file_reader, batchSize):
					for parsed in p.imap_unordered(parseLine, batch, chunksize=chunkSize):
						if isinstance(parsed, LogEntry):
							requestId = database.execute('INSERT INTO requests VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)', (parsed.request_time, parsed.remote_host, parsed.request_line, parsed.final_status, parsed.bytes_sent, parsed.remote_user, parsed.entry)).lastrowid
							database.executemany('INSERT INTO headers VALUES (?, ?, ?)', ((requestId, header, value) for header, value in parsed.headers_in.items()))
							ip = parsed.remote_host
							if ip not in seen_ips:
								data: dict = {
									'ip_address': ip,
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
								# City geolocation (with cache)
								if ipLocator is not None:
									cached_city = _city_cache.get(ip)
									if cached_city is None:
										with suppress(geoip2.errors.AddressNotFoundError):
											ipLocation: geoip2.models.City = ipLocator.city(ip)
											cached_city = {
												'city': ipLocation.city.name,
												'postal': ipLocation.postal.code,
												'country': ipLocation.country.name,
												'continent': ipLocation.continent.name,
												'latitude': ipLocation.location.latitude,
												'longitude': ipLocation.location.longitude,
												'radius': ipLocation.location.accuracy_radius
											}
										_city_cache[ip] = cached_city
									if cached_city:
										data.update(cached_city)
								# ASN lookup (with cache)
								if asnLocator is not None:
									cached_asn = _asn_cache.get(ip)
									if cached_asn is None:
										with suppress(geoip2.errors.AddressNotFoundError):
											asnLocation: geoip2.models.ASN = asnLocator.asn(ip)
											cached_asn = {
												'asn': asnLocation.autonomous_system_number,
												'asn_org': asnLocation.autonomous_system_organization
											}
										_asn_cache[ip] = cached_asn
									if cached_asn:
										data.update(cached_asn)
								database.execute('INSERT OR REPLACE INTO ip_geolocation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (data['ip_address'], data['city'], data['postal'], data['country'], data['continent'], data['latitude'], data['longitude'], data['radius'], data['asn'], data['asn_org']))
								seen_ips.add(ip)
						elif isinstance(parsed, str):
							database.execute('INSERT INTO requests (raw_line) VALUES (?)', (parsed,))
						contatore += 1
						now: float = time()
						elapsed: float = now - startProcess
						if now - lastPrint >= 1:
							print(f'{contatore}/{totaleLinee} {contatore//elapsed:.0f}r/s {elapsed:.0f}s', end='\r')
							lastPrint = now
					database.commit()

	# Cleanup and close
	print(f'Processo completato in {time() - startProcess:.0f} secondi')
	database.close()
	if ipLocator is not None:
		ipLocator.close()
	if asnLocator is not None:
		asnLocator.close()