CREATE TABLE requests (
	id_request INTEGER PRIMARY KEY AUTOINCREMENT,
	date_received TEXT DEFAULT NULL,
	ip_address TEXT DEFAULT NULL,
	request TEXT DEFAULT NULL,
	status_code INTEGER DEFAULT NULL,
	bytes_sent INTEGER DEFAULT NULL,
	remote_user TEXT DEFAULT NULL,
	raw_line TEXT NOT NULL
);

CREATE TABLE headers (
	id_request INTEGER NOT NULL,
	name TEXT NOT NULL,
	value TEXT
);

CREATE TABLE ip_geolocation (
	ip_address TEXT PRIMARY KEY NOT NULL,
	city TEXT,
	postal TEXT,
	country TEXT,
	continent TEXT,
	latitude REAL,
	longitude REAL,
	radius INTEGER,
	asn INTEGER,
	asn_org TEXT
);

CREATE INDEX idx_requests_date_received ON requests (date_received);
CREATE INDEX idx_requests_ip_address ON requests (ip_address);
CREATE INDEX idx_requests_request ON requests (request);