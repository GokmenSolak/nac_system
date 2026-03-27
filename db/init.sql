CREATE TABLE radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op VARCHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE radacct (
    radacctid bigserial PRIMARY KEY,
    acctsessionid varchar(64) NOT NULL DEFAULT '',
    acctuniqueid varchar(32) NOT NULL DEFAULT '',
    username varchar(64) NOT NULL DEFAULT '',
    nasipaddress inet NOT NULL,
    acctstarttime timestamp with time zone,
    acctupdatetime timestamp with time zone,
    acctstoptime timestamp with time zone,
    acctsessiontime bigint,
    acctinputoctets bigint,
    acctoutputoctets bigint,
    callingstationid varchar(50) NOT NULL DEFAULT '',
    calledstationid varchar(50) NOT NULL DEFAULT '',
    acctterminatecause varchar(32) NOT NULL DEFAULT ''
);

CREATE INDEX radcheck_username ON radcheck (username, attribute);
CREATE INDEX radacct_active_session ON radacct (acctsessionid, username) WHERE acctstoptime IS NULL;

ALTER TABLE radacct ADD CONSTRAINT radacct_sessionid_unique UNIQUE (acctsessionid);

INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('admin',    'Tunnel-Type',             ':=', 'VLAN'),
    ('admin',    'Tunnel-Medium-Type',      ':=', 'IEEE-802'),
    ('admin',    'Tunnel-Private-Group-Id', ':=', '20'),
    ('employee', 'Tunnel-Type',             ':=', 'VLAN'),
    ('employee', 'Tunnel-Medium-Type',      ':=', 'IEEE-802'),
    ('employee', 'Tunnel-Private-Group-Id', ':=', '10'),
    ('guest',    'Tunnel-Type',             ':=', 'VLAN'),
    ('guest',    'Tunnel-Medium-Type',      ':=', 'IEEE-802'),
    ('guest',    'Tunnel-Private-Group-Id', ':=', '30');

INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('admin1',   'Cleartext-Password', ':=', '$2b$12$tH0D/ttadpP08/2/yVsgcOtCDYL9.NVWnrlNofC2IOjz3n3KNXefK'),
    ('employee1','Cleartext-Password', ':=', '$2b$12$tH0D/ttadpP08/2/yVsgcOtCDYL9.NVWnrlNofC2IOjz3n3KNXefK'),
    ('guest1',   'Cleartext-Password', ':=', '$2b$12$tH0D/ttadpP08/2/yVsgcOtCDYL9.NVWnrlNofC2IOjz3n3KNXefK');

INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('admin1',    'admin',    1),
    ('employee1', 'employee', 1),
    ('guest1',    'guest',    1);

INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('AA:BB:CC:DD:EE:FF', 'MAC-Address', ':=', 'AA:BB:CC:DD:EE:FF');
INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('AA:BB:CC:DD:EE:FF', 'guest', 1);